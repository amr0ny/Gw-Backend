from distutils.util import strtobool

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError, DataError
from django.db.models import Q, Sum, F
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.generics import ListAPIView, GenericAPIView
from rest_framework.response import Response
from yaml import load as load_yaml, Loader
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from social_django.utils import load_strategy, load_backend
from social_core.exceptions import MissingBackend, AuthTokenError, AuthForbidden
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
import requests
from  orders.settings import SOCIAL_AUTH_GOOGLE_OAUTH2_KEY, SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET, SOCIAL_AUTH_GITHUB_KEY, SOCIAL_AUTH_GITHUB_SECRET

from backend.models import Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, Contact, \
    ConfirmEmailToken, OrderItem, Image
from backend.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    OrderSerializer, ContactSerializer, OrderItemSerializer, StatusSerializer
from backend.signals import new_user_registered, new_order


class RegisterAccount(GenericAPIView):
    """
    Для регистрации покупателей
    """

    serializer_class = UserSerializer

    # Регистрация методом POST
    def post(self, request, *args, **kwargs):

        # проверяем обязательные аргументы
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position'}.issubset(request.data):
            # проверяем пароль на сложность
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = []
                # noinspection PyTypeChecker
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}})
            else:
                # проверяем данные для уникальности имени пользователя
                # request.data._mutable = True
                request.data.update({})
                user_serializer = self.serializer_class(data=request.data)
                if user_serializer.is_valid():
                    # сохраняем пользователя
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()
                    new_user_registered.send(sender=self.__class__, user_id=user.id)
                    return JsonResponse({'Status': True})
                else:
                    return JsonResponse({'Status': False, 'Errors': user_serializer.errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class ConfirmAccount(GenericAPIView):
    """
    Класс для подтверждения почтового адреса
    """
    serializer_class = StatusSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            token = serializer.validated_data['token']

            token = ConfirmEmailToken.objects.filter(user__email=email, key=token).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': 'Неправильно указан токен или email'})

        return JsonResponse({'Status': False, 'Errors': serializer.errors})
    
    
class AccountDetails(GenericAPIView):
    """
    Класс для работы данными пользователя
    """

    serializer_class = UserSerializer

    # получить данные
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        serializer = self.serializer_class(request.user)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        user_data = request.data.copy()
        avatar_file = request.FILES.get('avatar')

        if avatar_file:
            # Create or update the Image instance
            image, created = Image.objects.get_or_create(type='user')
            image.image = avatar_file
            image.save()
            user_data['avatar'] = image.id

        if 'password' in request.data and request.data['password'] not in ['', None]:
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}})
            else:
                request.user.set_password(request.data['password'])

        user_serializer = self.serializer_class(request.user, data=user_data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors})


class LoginAccount(GenericAPIView):
    """
    Класс для авторизации пользователей
    """

    serializer_class = StatusSerializer

    # Авторизация методом POST
    def post(self, request, *args, **kwargs):

        if {'email', 'password'}.issubset(request.data):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None:
                if user.is_active:
                    token, _ = Token.objects.get_or_create(user=user)

                    return JsonResponse({'Status': True, 'Token': token.key})

            return JsonResponse({'Status': False, 'Errors': 'Не удалось авторизовать'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class CategoryView(ListAPIView):
    """
    Класс для просмотра категорий
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    @method_decorator(cache_page(60 * 15))  # Кэширование на 15 минут
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer

    @method_decorator(cache_page(60 * 15))  # Кэширование на 15 минут
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoView(GenericAPIView):
    """
    Класс для поиска товаров
    """

    serializer_class = ProductInfoSerializer
    parser_classes = (MultiPartParser, FormParser)
    @method_decorator(cache_page(60 * 15))  # Кэширование на 15 минут
    def get(self, request, *args, **kwargs):
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        #фильтруем и отбрасываем дупликаты
        queryset = ProductInfo.objects.filter(query).select_related('shop', 'product__category').prefetch_related('product_parameters__parameter').distinct()

        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Unauthorized'}, status=403)

        product_data = request.data.copy()
        image_file = request.FILES.get('image')

        if image_file:
            image, created = Image.objects.get_or_create(type='product')
            image.image = image_file
            image.save()
            product_data['image'] = image.id

        serializer = self.serializer_class(data=product_data)
        if serializer.is_valid():
            product_info = serializer.save()
            return JsonResponse({'Status': True, 'id': product_info.id})
        else:
            return JsonResponse({'Status': False, 'Errors': serializer.errors})

    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Unauthorized'}, status=403)

        product_id = request.data.get('id')
        if not product_id:
            return JsonResponse({'Status': False, 'Errors': 'Product ID is required'})

        try:
            product_info = ProductInfo.objects.get(id=product_id, shop__user=request.user)
        except ProductInfo.DoesNotExist:
            return JsonResponse({'Status': False, 'Errors': 'Product not found'})

        product_data = request.data.copy()
        image_file = request.FILES.get('image')

        if image_file:
            image, created = Image.objects.get_or_create(type='product')
            image.image = image_file
            image.save()
            product_data['image'] = image.id

        serializer = self.serializer_class(product_info, data=product_data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Errors': serializer.errors})


class BasketView(GenericAPIView):
    """
    Класс для работы с корзиной пользователя
    """

    def get_serializer_class(self):
        if self.request.method == 'GET':
            return OrderSerializer
        if self.request.method == 'POST':
            return OrderItemSerializer
        return OrderSerializer

    @method_decorator(cache_page(60 * 15))  # Кэширование на 15 минут
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)
        basket = Order.objects.filter(user_id=request.user.id, state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()
        serializer = self.get_serializer_class()(basket, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if {'items'}.issubset(request.data):
            if type(request.data['items']) is list:
                items_dict = request.data['items']
            else:
                return JsonResponse({'Status': False, 'Errors': 'Неверный формат запроса'})

            basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
            objects_created = 0
            for order_item in items_dict:
                order_item.update({'order': basket.id})
                serializer = self.get_serializer_class()(data=order_item)
                if serializer.is_valid():
                    try:
                        serializer.save()
                    except IntegrityError as error:
                        return JsonResponse({'Status': False, 'Errors': str(error)})
                    else:
                        objects_created += 1
                else:
                    return JsonResponse({'Status': False, 'Errors': serializer.errors})

            return JsonResponse({'Status': True, 'Создано объектов': objects_created})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        items_sting = request.data.get('items')
        if items_sting:
            items_list = items_sting.split(',')
            basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
            query = Q()
            objects_deleted = False
            for order_item_id in items_list:
                if order_item_id.strip().isdigit():
                    query = query | Q(order_id=basket.id, id=order_item_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = OrderItem.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if {'items'}.issubset(request.data):
            if type(request.data['items']) is list:
                items_dict = request.data['items']
            else:
                return JsonResponse({'Status': False, 'Errors': 'Неверный формат запроса'})

            basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
            objects_updated = 0
            for order_item in items_dict:
                if type(order_item['id']) is int and type(order_item['quantity']) is int:
                    objects_updated += OrderItem.objects.filter(order_id=basket.id, id=order_item['id']).update(
                        quantity=order_item['quantity'])

            return JsonResponse({'Status': True, 'Обновлено объектов': objects_updated})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class PartnerUpdate(GenericAPIView):
    """
    Класс для обновления прайса от поставщика
    """

    serializer_class = StatusSerializer

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Только для магазинов'}, status=403)

        file = request.FILES.get('file')
        if file:
            try:
                data = load_yaml(file, Loader=Loader)

                shop, _ = Shop.objects.get_or_create(name=data['shop'], user_id=request.user.id)
                if 'url' in data.keys() and shop.url != data['url']:
                    shop.url = data['url']
                    shop.save()

                for category in data['categories']:
                    category_object, _ = Category.objects.get_or_create(id=category['id'], name=category['name'])
                    category_object.shops.add(shop.id)
                    category_object.full_clean()
                    category_object.save()

                ProductInfo.objects.filter(shop_id=shop.id).delete()
                for item in data['goods']:
                    product, _ = Product.objects.get_or_create(name=item['name'], category_id=item['category'])

                    product_info = ProductInfo.objects.create(product_id=product.id, external_id=item['id'],
                                                              model=item['model'], price=item['price'],
                                                              price_rrc=item['price_rrc'], quantity=item['quantity'],
                                                              shop_id=shop.id)
                    for name, value in item['parameters'].items():
                        parameter_object, _ = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(product_info_id=product_info.id,
                                                        parameter_id=parameter_object.id, value=value)

                return JsonResponse({'Status': True})
            except (IntegrityError, DataError, ValidationError) as e:
                return JsonResponse({'Status': False, 'Errors': str(e)})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class PartnerState(GenericAPIView):
    """
    Класс для работы со статусом поставщика
    """

    serializer_class = ShopSerializer

    # получить текущий статус
    @method_decorator(cache_page(60 * 15))  # Кэширование на 15 минут
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Только для магазинов'}, status=403)
        try:
            shop = request.user.shop
            serializer = self.serializer_class(shop)
            return Response(serializer.data)
        except AttributeError as error:
            return JsonResponse({'Status': False, 'Errors': str(error)})

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Только для магазинов'}, status=403)

        state = request.data.get('state')
        if state:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=strtobool(state))
                return JsonResponse({'Status': True})
            except ValueError as error:
                return JsonResponse({'Status': False, 'Errors': str(error)})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class PartnerOrders(GenericAPIView):
    """
    Класс для получения заказов поставщиками
    """

    serializer_class = OrderSerializer

    @method_decorator(cache_page(60 * 15))
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Только для магазинов'}, status=403)

        order = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = self.serializer_class(order, many=True)
        return Response(serializer.data)


class ContactView(GenericAPIView):
    """
    Класс для работы с контактами покупателей
    """

    serializer_class = ContactSerializer

    # получить мои контакты
    @method_decorator(cache_page(60 * 15))
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)
        contact = Contact.objects.filter(user_id=request.user.id)
        serializer = self.serializer_class(contact, many=True)
        return Response(serializer.data)

    # добавить новый контакт
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if {'city', 'street', 'phone'}.issubset(request.data):
            # request.data._mutable = True
            request.data.update({'user': request.user.id})
            if {'phone'}.issubset(request.data) and request.data.get('phone'):
                request.data.update({'type': 'phone'})
            else:
                request.data.update({'type': 'address'})
            serializer = self.serializer_class(data=request.data)

            if serializer.is_valid():
                serializer.save()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': serializer.errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    # удалить контакт
    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        items_sting = request.data.get('items')
        if items_sting:
            items_list = items_sting.split(',')
            query = Q()
            objects_deleted = False
            for contact_id in items_list:
                if contact_id.isdigit():
                    query = query | Q(user_id=request.user.id, id=contact_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = Contact.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    # редактировать контакт
    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if 'id' in request.data:
            if request.data['id'].isdigit():
                contact = Contact.objects.filter(id=request.data['id'], user_id=request.user.id).first()
                request.data['type'] = contact.type
                print(contact)
                if contact:
                    serializer = self.serializer_class(contact, data=request.data, partial=True)
                    if serializer.is_valid():
                        serializer.save()
                        return JsonResponse({'Status': True})
                    else:
                        return JsonResponse({'Status': False, 'Errors': serializer.errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class OrderView(GenericAPIView):
    """
    Класс для получения и размешения заказов пользователями
    """

    serializer_class = OrderSerializer

    # получить мои заказы
    @method_decorator(cache_page(60 * 15))
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)
        order = Order.objects.filter(user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = self.serializer_class(order, many=True)
        return Response(serializer.data)

    # разместить заказ из корзины
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if {'id', 'contact'}.issubset(request.data):
            if request.data['id'].isdigit():
                try:
                    is_updated = Order.objects.filter(user_id=request.user.id, id=request.data['id']).update(
                        contact_id=request.data['contact'], state='new')
                except IntegrityError:
                    return JsonResponse({'Status': False, 'Errors': 'Неправильно указаны аргументы'})
                else:
                    if is_updated:
                        new_order.send(sender=self.__class__, user_id=request.user.id)
                        return JsonResponse({'Status': True})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


import logging
logger = logging.getLogger(__name__)

class SocialAuthView(GenericAPIView):
    def post(self, request):
        provider = request.data.get('provider')
        code = request.data.get('code')
        redirect_uri = request.data.get('redirect_uri')

        if not all([provider, code, redirect_uri]):
            return Response({'error': 'Please provide provider, code, and redirect_uri'}, 
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            strategy = load_strategy(request)
            backend = load_backend(strategy=strategy, name=provider, redirect_uri=None)

            # Получаем CLIENT_ID и SECRET в зависимости от провайдера
            if provider == 'google-oauth2':
                client_id = SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
                client_secret = SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET
            elif provider == 'github':
                client_id = SOCIAL_AUTH_GITHUB_KEY
                client_secret = SOCIAL_AUTH_GITHUB_SECRET
            else:
                return Response({'error': 'Unsupported provider'}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # Получаем access_token с помощью кода
            token_url = backend.access_token_url()
            token_payload = {
                'client_id': client_id,
                'client_secret': client_secret,
                'code': code,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }

            # Для GitHub нужно добавить заголовок Accept
            headers = {'Accept': 'application/json'} if provider == 'github' else {}

            token_response = requests.post(token_url, data=token_payload, headers=headers)
            token_data = token_response.json()

            if 'access_token' not in token_data:
                return Response({'error': 'Failed to obtain access token', 'details': token_data}, 
                                status=status.HTTP_400_BAD_REQUEST)

            access_token = token_data['access_token']

            # Аутентификация пользователя с помощью полученного access_token
            user = backend.do_auth(access_token)

            if user:
                user.is_active = True
                user.save()
                token, created = Token.objects.get_or_create(user=user)
                refresh = RefreshToken.for_user(user)
                return Response({
                    'token': str(token.key),
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Authentication failed'}, 
                                status=status.HTTP_400_BAD_REQUEST)

        except MissingBackend:
            return Response({'error': 'Please provide a valid provider'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        except (AuthForbidden, Exception) as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
class SentryErrorView(GenericAPIView):
    def get(self, request):
        return Response({'result': 1/0})
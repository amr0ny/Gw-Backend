from rest_framework import serializers

from backend.models import User, Category, Shop, ProductInfo, Product, ProductParameter, OrderItem, Order, Contact, Image


class ImageSerializer(serializers.Serializer):
    class Meta:
        model = Image
        fields = (id, 'type', 'image', 'thumbnail')



class StatusSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField()

    def validate(self, data):
        if 'email' not in data:
            raise serializers.ValidationError("Поле [email] должно быть заполнено")
        if 'token' not in data:
            raise serializers.ValidationError("Поле [token] должно быть заполнено")
        return data
    

class ContactSerializer(serializers.ModelSerializer):
    def validate(self, attrs):
        if attrs['type'] == 'phone':
            if not attrs['phone']:
                raise serializers.ValidationError('Поле [phone] должно быть заполнено')
            return attrs
        elif attrs['type'] == 'address':
            if not attrs['city']:
                raise serializers.ValidationError('Поле [city] должно быть заполнено')
            return attrs

    class Meta:
        model = Contact
        fields = ('id', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'user', 'phone', 'type')
        read_only_fields = ('id',)
        extra_kwargs = {'type': {'write_only': True}, 'user': {'write_only': True}}


class UserSerializer(serializers.ModelSerializer):
    contacts = ContactSerializer(read_only=True, many=True, required=False)
    avatar = ImageSerializer(read_only=True, required=False)
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'company', 'position', 'contacts', 'avatar',)
        read_only_fields = ('id',)


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ('id', 'name',)
        read_only_fields = ('id',)


class ShopSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shop
        fields = ('id', 'name', 'state', 'url', 'user')
        read_only_fields = ('id',)
        extra_kwargs = {'user': {'write_only': True}}


class ProductSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ('name', 'category',)


class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ('parameter', 'value',)


class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)
    image = ImageSerializer(read_only=True, required=False)

    class Meta:
        model = ProductInfo
        fields = ('id', 'model', 'product', 'shop', 'quantity', 'price', 'price_rrc', 'product_parameters', 'image', )
        read_only_fields = ('id',)


class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ('id', 'product_info', 'quantity', 'order',)
        read_only_fields = ('id',)
        extra_kwargs = {'order': {'write_only': True}}


class OrderItemCreateSerializer(OrderItemSerializer):
    product_info = ProductInfoSerializer(read_only=True)


class OrderSerializer(serializers.ModelSerializer):
    ordered_items = OrderItemCreateSerializer(read_only=True, many=True)

    total_sum = serializers.IntegerField()
    contact = ContactSerializer(read_only=True)

    class Meta:
        model = Order
        fields = ('id', 'ordered_items', 'state', 'dt', 'total_sum', 'contact',)
        read_only_fields = ('id',)

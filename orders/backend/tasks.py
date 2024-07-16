from celery import shared_task
from django.core.mail import EmailMultiAlternatives
from imagekit import ImageSpec
from imagekit.processors import ResizeToFit
from backend.models import Image

@shared_task
def send_mail(subject, body, from_email, to_email):
    msg = EmailMultiAlternatives(subject, body, from_email, to_email)
    msg.send()


class Thumbnail(ImageSpec):
    processors = [ResizeToFit(100, 100)]
    format = 'JPEG'
    options = {'quality': 60}

@shared_task
def create_thumbnails(id):
    instance = Image.objects.get(id=id)
    field = getattr(instance, 'image')

    if field:
        thumbnail = Thumbnail(source=field)
        thumbnail.generate()

        instance.thumbnail = thumbnail
        instance.save()
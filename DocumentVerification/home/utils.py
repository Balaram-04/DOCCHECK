from django.utils.crypto import get_random_string
import random

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(user):
    otp = generate_otp()
    user.otp = otp
    user.otp_created_at = datetime.now()
    user.save()

    send_mail(
        'Your OTP for Account Verification',
        f'Your OTP is: {otp}. It is valid for 10 minutes.',
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )

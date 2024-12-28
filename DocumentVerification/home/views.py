from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from .models import User
from django.contrib.auth import get_user_model, login
import re , random
from django.contrib.auth import authenticate #, login ,logout
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils.timezone import now, timedelta
from django.contrib.auth.decorators import login_required
from .utils import send_otp 


def index(request):
    return render(request, 'home/index.html')

# Utility function to generate a 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))

otp_storage = {}
def user_login(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        otp = request.POST.get('otp')

        if not email:
            messages.error(request, 'Email is required.')
            return render(request, 'home/login.html', {'email': email})

        # Step 1: Send OTP
        if not otp:
            generated_otp = generate_otp()
            otp_storage[email] = generated_otp

            send_mail(
                subject='Your Login OTP',
                message=f'Your OTP for login: {generated_otp}',
                from_email='noreply@example.com',
                recipient_list=[email],
                fail_silently=False,
            )

            messages.success(request, 'OTP has been sent to your email.')
            return render(request, 'home/login.html', {'email': email, 'otp_sent': True})

        # Step 2: Verify OTP
        saved_otp = otp_storage.get(email)
        if saved_otp and str(saved_otp) == otp:
            User = get_user_model()
            try:
                user = User.objects.get(email=email)
                if user:
                    login(request, user)
                    messages.success(request, 'Login successful!')
                    otp_storage.pop(email, None)
                    return redirect('dashboard')
                else:
                    messages.error(request, 'No account associated with this email.')
                    return render(request, 'home/login.html', {'email': email})
            except User.DoesNotExist:
                messages.error(request, 'No account associated with this email.')
                return render(request, 'home/login.html', {'email': email})
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
            return render(request, 'home/login.html', {'email': email, 'otp_sent': True})

    return render(request, 'home/login.html')




def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,12}$'

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'home/signup.html')

        if not re.match(password_pattern, password):
            messages.error(request, (
                'Password must be 8-12 characters long, contain at least one uppercase letter, '
                'one number, and one special character.'
            ))
            return render(request, 'home/signup.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return render(request, 'home/signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'home/signup.html')
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            otp = generate_otp()
            user.otp = otp
            user.otp_created_at = now()
            user.save()
            send_mail(
                'Your OTP for Account Verification',
                f'Your OTP is: {otp}. It is valid for 5 minutes.',
                'your_email@example.com',  # Replace with your email host
                [email],
                fail_silently=False,
            )

            messages.success(request, "Account created! Check your email for the OTP.")
            return redirect('verify_otp', user_id=user.id)

        except Exception as e:
            messages.error(request, f"An error occurred: {e}")
            return render(request, 'home/signup.html')

        

   
    return render(request, 'home/signup.html')


def verify_otp(request, user_id):
    # Retrieve the user object
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        entered_otp = request.POST.get('otp')  # Get OTP from the POST data

        # Check if OTP has expired
        if user.otp == entered_otp:
            if now() - user.otp_created_at > timedelta(minutes=5):
                messages.error(request, "OTP expired. Please request a new one.")
                return redirect('resend_otp', user_id=user.id)

            # If OTP is correct and not expired, verify the user
            user.is_verified = True
            user.otp = None  # Clear the OTP after successful verification
            user.save()
            messages.success(request, "Account verified! You can now log in.")
            return redirect('login')

        else:
            # If OTP is incorrect
            messages.error(request, "Invalid OTP. Please try again.")

    # Render the OTP verification template
    return render(request, 'home/verify_otp.html', {'user': user})

def resend_otp(request, user_id):
    user = get_object_or_404(User, id=user_id)

    if not user.is_verified:
        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = now()
        user.save()

        send_mail(
            'Your OTP for Account Verification (Resent)',
            f'Your new OTP is: {otp}. It is valid for 5 minutes.',
            'your_email@example.com',  # Replace with your email host
            [user.email],
            fail_silently=False,
        )
        messages.success(request, "A new OTP has been sent to your email.")
        return redirect('verify_otp', user_id=user.id)

    messages.error(request, "User already verified.")
    return redirect('login')

def logout(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return render(request, 'home/login.html')
@login_required
def dashboard(request):
    user = request.user
    profile_data = {
        'email': user.email,
        'name': user.first_name or user.username,
        # Add any additional user-specific information here
    }
    return render(request, 'dashboard.html', {'profile': profile_data})



def forget_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()

        if user:
            # Generate a unique token (you can use uuid or Django's built-in token generation)
            token = generate_otp()  # You can replace with a secure token logic
            user.otp = token
            user.otp_created_at = now()
            user.save()

            # Send reset password link via email
            reset_link = request.build_absolute_uri(reverse('reset_password', args=[user.id, token]))
            send_mail(
                'Reset Your Password',
                f'Click the link below to reset your password:\n{reset_link}\n\nThis link will expire in 5 minutes.',
                'your_email@example.com',  # Replace with your email host
                [email],
                fail_silently=False,
            )
            messages.success(request, "A password reset link has been sent to your email.")
        else:
            messages.error(request, "No user found with this email address.")
        return redirect('forget_password')

    return render(request, 'home/forget_password.html')

def reset_password(request, user_id, token):
    user = get_object_or_404(User, id=user_id)

    # Validate token and expiration
    if user.otp != token or now() - user.otp_created_at > timedelta(minutes=5):
        messages.error(request, "Invalid or expired reset link.")
        return redirect('forget_password')

    if request.method == 'POST':
        new_password = request.POST.get('password')
        user.password = make_password(new_password)
        user.otp = None  # Clear OTP after password update
        user.save()
        messages.success(request, "Password updated successfully! You can now log in.")
        return redirect('login')

    return render(request, 'home/reset_password.html', {'user': user})


def profile(request):
    pass
def settings(request):
    pass
def edit_profile(request):
    pass
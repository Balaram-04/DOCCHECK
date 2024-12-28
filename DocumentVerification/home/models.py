from django.db import models
from django.contrib.auth.hashers import make_password

class UserManager(models.Manager):
    def create_user(self, username, email, password, is_verified=False, otp=None, otp_created_at=None):
        if not email:
            raise ValueError("The Email field must be set")
        if not username:
            raise ValueError("The Username field must be set")
    
        hashed_password = make_password(password)
        user = self.model(
        username=username, 
        email=email, 
        password=hashed_password,
        is_verified=is_verified,
        otp=otp,
        otp_created_at=otp_created_at
        )
        user.save(using=self._db)
        return user


class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    is_verified = models.BooleanField(default=False)  
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)

    objects = UserManager()

    def __str__(self):
        return self.username


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True)
    #avatar = models.ImageField(upload_to='avatars/', blank=True)
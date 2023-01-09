from django.db import models

from django.contrib.auth.models import(
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)


class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if username is None:
            raise TypeError('Users should have a username')  
        if email is None:
            raise TypeError('Users should have an email')

        user=self.model(
            username=username,
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError('Users should have a password')  

        user=self.create_user(
            username=username,
            email=email,
            password=password,
        )
        user.is_superuser=True,
        user.is_stuff=True,
        user.save()
        return user    
        

class User(AbstractBaseUser, PermissionsMixin):
    username=models.CharField(
        max_length=25,
        unique=True,
        null=True,
        db_index=True
    )
    email=models.EmailField(
        max_length=25,
        unique=True,
        null=True,
        db_index=True
    )
    is_verified=models.BooleanField(default=False)
    is_active=models.BooleanField(default=True)
    is_stuff=models.BooleanField(default=False)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True) 

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects=UserManager()

    def __str__(self):
        return self.email

    def tokend(self):
        return ''             

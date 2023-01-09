from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from users.users_app.serializers import RegisterSerializer


class RegisterView(generics.GenericAPIView):

    serializer_class=RegisterSerializer

    def post(self, request):
        user=request.data
        # Send data to our RegisterSerializer
        serializer=self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Here we get a data from RegisterSerializer
        user_data=serializer.data

        return Response(
            user_data,
            status=status.HTTP_201_CREATED,
        )

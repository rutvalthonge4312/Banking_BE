from django.shortcuts import render
from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
import re
from useronbording.models import User
from .models import Account
from .serializer import CreateAccountSerializer
from rest_framework.permissions import IsAuthenticated,IsAdminUser



@api_view(['POST'])
@permission_classes([IsAdminUser])
def openAccountNumber(request):
    try:
        data=request.data
        serializer_data=CreateAccountSerializer(data=data)
        if(serializer_data.is_valid()):
            bank_name="State Bank of MyWorld"
            phone=request.data['phone']
            balance=request.data['amount']
            account_type=request.data['accountType']
            m_pin=request.data['mPin']
            m_pin=str(m_pin)
            if not phone:
                return Response({'message': 'Please Enter Mobile Number'}, status=status.HTTP_400_BAD_REQUEST)
            if not m_pin:
                return Response({'message': 'Please give m-pin, for further transcations!'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                if(len(m_pin)!=4):
                    return Response({'message': 'm-Pin must be of 4 digits'}, status=status.HTTP_400_BAD_REQUEST)
            user=User.objects.filter(phone_number=phone).exists()
            if(user):
                user = User.objects.filter(phone_number=phone).first()
                if(user.isAccount):
                    return Response({'message': 'Already Have Account!'}, status=status.HTTP_400_BAD_REQUEST)
                user.isAccount=True
                if(Account.objects.exists()):
                    last_accoutNumber=Account.objects.last()
                    newaccountNumber=last_accoutNumber.account_number+1
                else:
                    newaccountNumber=10001
                account = Account(
                    bank_name=bank_name,
                    account_type=account_type,
                    balance=balance,
                    customer=user,
                    m_pin=m_pin,
                    account_number=newaccountNumber
                )
                user.save()
                account.save()
                return Response({'message': 'Successfully opened Account!'}, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'User with this mobile number does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            error=serializer_data.errors
            return Response({"message":error }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        print(e)
        return Response({'message': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

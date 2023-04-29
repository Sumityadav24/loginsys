from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.contrib.sites.shortcuts import get_current_site
from django.contrib import messages
from gfglogin import settings
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from .tokens import gentoken
# Create your views here.


def index(request):
    return render(request, "authentication/index.html")


def signup(request):

    if request.method == 'POST':
        usr = request.POST.get('usr')
        ln = request.POST.get('ln')
        fn = request.POST.get('fn')
        email = request.POST.get('email')
        fpass = request.POST.get('pass')
        cpass = request.POST.get('cpass')
        if User.objects.filter(username=usr).exists():
            messages.error(
                request, "This is user name is already taken sorry Tr Different")
            return redirect('home')
        if User.objects.filter(email=email).exists():
            messages.error(
                request, "This is Email is already taken sorry Tr Different")
            return redirect('home')
        if fpass != cpass:
            messages.error(request, "Password doent match")
            return redirect('home')
        else:
            myusr = User.objects.create_user(
                username=usr, email=email, password=fpass)
            myusr.first_name = fn
            myusr.last_name = ln
            myusr.is_active = False
            messages.success(request, "Your account Created succesfully")
            myusr.save()
            # Welcome Email
            sub = "Hare Krishna Welcome eLogin"
            msg = f"Hello, {myusr.first_name } !! \n Welcome To HK \n Thank You for registrating on our website \n we have sent an conformation link please confirm our email in order to activate our account"
            f_e = settings.EMAIL_HOST_USER
            to_e = [myusr.email]
            send_mail(sub, msg, f_e, to_e)

            # email confirmation
            site = get_current_site(request)
            email2 = "Confirm you email please"
            msg2 = render_to_string('emailconf.html', {
                'name': myusr.first_name,
                'domain': site.domain,
                'uid': urlsafe_base64_encode(force_bytes(myusr.pk)),
                'token': gentoken.make_token(myusr)

            })
            em = EmailMessage(
                email2,
                msg2,
                settings.EMAIL_HOST_USER,
                [myusr.email],
            )
            em.send()
        return redirect('home')
    else:
        return render(request, 'authentication/signup.html')


def signin(request):
    if request.method == 'POST':
        usr = request.POST.get('usr')
        fpass = request.POST.get('pass')
        muser = authenticate(username=usr, password=fpass)
        if muser is not None:
            login(request, muser)
            fn = muser.first_name
            messages.success(request, "You logged In Successfully!")
            return render(request, 'authentication/index.html', {'fn': fn})

        else:
            messages.error(request, "Bad Crendentials")
            return redirect('signup')
    return render(request, 'authentication/signin.html')


def signout(request):
    logout(request)
    messages.success(request, 'Logged Out Succcessfully')
    return redirect('home')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myusr = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myusr = None
    if myusr is not None and gentoken.check_token(myusr, token):
        myusr.is_active = True
        myusr.save()
        login(request, myusr)
        messages.success(request, "Your account is now active")
        return redirect('home')
    else:
        return render(request, 'failed.html')

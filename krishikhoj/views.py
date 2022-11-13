from django.shortcuts import render, HttpResponse, redirect
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.conf import settings
from django.core.mail import send_mail
import random
from django.core.cache import cache, caches
from .models import Tractor
import json
import uuid

# Create your views here.


def sending_mail(gmail, token):
    subject = "krishiKhoj Wants Your Profile Needs to be verified"
    message = f"Paste This OTP in Authentication Field {token}"
    sender = settings.EMAIL_HOST_USER
    reciptent = [gmail]
    send_mail(subject, message, sender, reciptent)


def generate_otp():
    my_otp = ""
    for i in range(6):
        my_otp += str(random.randint(0, 9))
    return my_otp


def logout_up(request):
    if not request.user.is_anonymous:
        logout(request)
        return redirect('login')
    else:
        request.build_absolute_uri("")
        return redirect('/')


def home(request):
    if request.user.is_authenticated:
        my_tracs = Tractor.objects.filter(farmer=request.user)
        if len(my_tracs) == 0:
            return render(request, "home.html", context={'error': "No Tractor Records present create one by clicking on '''Create Tractor''' option above"})
        else:
            return render(request, "home.html", context={'data': my_tracs})
    else:
        return render(request, "home.html", context={'error': "First Login Than you will able to see you records"})


def verify(request, data=None):
    if request.method == 'GET':
        if data == None:
            return redirect('signup')
        if not cache.get(data):
            return redirect('signup')
        return render(request, "verify.html", context={'email': data})
    elif request.method == 'POST':
        otp = str(request.POST.get('otp'))
        if not cache.get(data):
            return render(request, "verify.html", context={'email': data, 'error': "invalid gmail or your session has expired. please re-signup again"})
        if len(otp) != 6:
            return render(request, "verify.html", context={'email': data, 'error': "opt must be of 6 characters"})
        lol = cache.get(data)['email']
        if not cache.get(f'{lol}_otp'):
            return render(request, "verify.html", context={'email': data, 'error': "opt expired please use resend"})
        else:
            if otp != cache.get(f'{lol}_otp'):
                return render(request, "verify.html", context={'email': data, 'error': "Invalid Otp please retry"})
            elif otp == cache.get(f'{lol}_otp'):
                my_all_data = cache.get(data)
                inst = User.objects.create(email=my_all_data['email'],
                                           username=my_all_data['username'],
                                           first_name=my_all_data['name'])
                inst.set_password(my_all_data['password'])
                inst.save()
                return redirect('login')


def resend_otp(request, gmail):
    if request.method == 'GET':
        if not cache.get(gmail):
            request.build_absolute_uri("")
            return redirect("/")
        otp = generate_otp()
        sending_mail(gmail, otp)
        cache.set(f'{gmail}_otp', otp, 300)

        request.build_absolute_uri("")
        return redirect(f"/verify/{gmail}")
    request.build_absolute_uri("")
    return redirect("/")


def signup(request):
    try:
        if request.method == 'GET':
            if not request.user.is_anonymous:
                request.build_absolute_uri("")
                return redirect("/")
            return render(request, "signup.html")
        if request.method == 'POST':
            print(request.POST)
            gmail = request.POST['email']
            username = request.POST['username']
            password = request.POST['password']
            full_name = request.POST['full_name']
            conf_password = request.POST['pass']
            if "@" not in str(gmail):
                return render(request, "signup.html", context={"error": "Email Must be valid and contains @"})

            if len(User.objects.filter(email=gmail)) > 0:
                return render(request, "signup.html", context={"error": "User with this email already exist"})

            if len(full_name) < 3:
                return render(request, "signup.html", context={'error': "your name must be greater than 2 characters"})

            if username == "" or len(str(username)) < 5:
                return render(request, "signup.html", context={"error": "username should be valid and should be greater than 4 characters"})

            if len(User.objects.filter(username=username)) > 0:
                return render(request, "signup.html", context={"error": "username already taken please choose a different one"})

            if password == "" or len(str(password)) < 4:
                return render(request, "signup.html", context={"error": "password must be valid and greater than 3 characters"})
            if conf_password == "" or len(str(conf_password)) < 4:
                return render(request, "signup.html", context={"error": "password must be valid and greater than 3 characters"})
            if password != conf_password:
                return render(request, "signup.html", context={"error": "Both the passwords must be same"})

            # Registering user in the databases
            otp = generate_otp()
            cache.set(f'{gmail}', {
                'username': username,
                'email': gmail,
                'password': password,
                'name': full_name
            }, 1200)

            cache.set(f'{gmail}_otp', otp, 300)

            sending_mail(gmail, otp)

            return redirect(f'verify/{gmail}')
            # inst = User.objects.create(email=gmail, username=username)
            # inst.set_password(str(conf_password))
            # inst.save()

            # return redirect('login')
    except Exception as e:
        return render(request, "signup.html", context={"error": "Something went wrong please try again"})


def login_up(request):
    try:
        if request.method == 'GET':
            if not request.user.is_anonymous:
                request.build_absolute_uri("")
                return redirect("/")
            return render(request, "login.html")
        if request.method == 'POST':
            gmail = request.POST['email']
            password = request.POST['password']

            if "@" not in gmail:
                return render(request, "login.html", context={"error": "email must be valid"})

            if len(User.objects.filter(email=gmail)) == 0:
                return render(request, "login.html", context={"error": "No farmer with this email is founded"})

            cur_inst = User.objects.get(email=gmail)
            if cur_inst.check_password(password):
                login(request, cur_inst)
                request.build_absolute_uri("")
                return redirect("/")
            else:
                return render(request, "login.html", context={"error": "No farmer with this cridentials founded"})
    except Exception as e:
        return render(request, "login.html", context={"error": "Something Went wrong please try again"})


def add_tractor(request):
    try:
        if request.method == 'GET':
            if request.user.is_anonymous:
                request.build_absolute_uri("")
                return redirect('login')
            else:
                return render(request, "create_tractor.html")
        if request.method == 'POST':
            for i in request.POST.items():
                if i[1] == "":
                    return render(request, "create_tractor.html", context={'glob_error': "All the fields must be filled or selected according to given constraints"})
            if len(str(request.POST.get('brand'))) < 3:
                return render(request, "create_tractor.html", context={'glob_error': "Brand name should be greater than 3 characters"})

            if len(str(request.POST.get('trac_name'))) < 3:
                return render(request, "create_tractor.html", context={'glob_error': "tractor name should be greater than 3 characters"})

            if len(Tractor.objects.filter(naming=str(request.POST.get('trac_name')))) > 0:
                return render(request, "create_tractor.html", context={'glob_error': "tractor name already taken please choose different one"})

            if len(str(request.POST.get('rpm'))) > 4:
                return render(request, "create_tractor.html", context={'glob_error': "rpm should be smaller than or equal to 9999"})

            if str(request.POST.get('driver_seat')) != 'Linear' and str(request.POST.get('driver_seat')) != 'Granular':
                return render(request, "create_tractor.html", context={'glob_error': "Driver Seat should be Linear or Granular"})

            if str(request.POST.get('cab')) != 'Silent-blocks' and str(request.POST.get('cab')) != 'Pneumatic springs':
                return render(request, "create_tractor.html", context={'glob_error': "Cab Suspension should be Pneumatic springs or Silent-blocks"})

            if str(request.POST.get('axle')) != 'Yes' and str(request.POST.get('axle')) != 'No':
                return render(request, "create_tractor.html", context={'glob_error': "Front Axle Suspension Seat should be Yes or No"})

            if str(request.POST.get('wheel')) != '4wd' and str(request.POST.get('wheel')) != '2wd':
                return render(request, "create_tractor.html", context={'glob_error': "Wheel should be 4wd or 2wd"})

            if str(request.POST.get('gear')) != 'Fully Synchronized' and str(request.POST.get('gear')) != 'Automatic Power Shift':
                return render(request, "create_tractor.html", context={'glob_error': "Gear Box Type should be Fully Synchronized or Automatic Power Shift"})

            if str(request.POST.get('power')) != 'Yes' and str(request.POST.get('power')) != 'No':
                return render(request, "create_tractor.html", context={'glob_error': "Front Power Take-off should be Yes or No"})

            if len(request.POST.getlist('Lol')) <= 0:
                return render(request, "create_tractor.html", context={'glob_error': "A Single implementation must be selected"})

            if str(request.POST.get('axle')) == 'Yes':
                axle_data = True
            elif str(request.POST.get('axle')) == 'No':
                axle_data = False

            if str(request.POST.get('power')) == 'Yes':
                power_data = True
            elif str(request.POST.get('power')) == 'No':
                power_data = False

            track = Tractor.objects.create(
                farmer=request.user,
                brand=str(request.POST.get('brand')),
                naming=str(request.POST.get('trac_name')),
                drivers_seat=str(request.POST.get('driver_seat')),
                cab_suspension=str(request.POST.get('cab')),
                front_axle_suspension=axle_data,
                wheel_drive=str(request.POST.get('wheel')),
                gear_box_type=str(request.POST.get('gear')),
                implementations=json.dumps(request.POST.getlist('Lol')),
                rpm=int(request.POST.get('rpm')),
                pto=power_data,
                trac_id=uuid.uuid4()
            )
            track.save()

            return render(request, "create_tractor.html", context={'success': "Succesfully Saved Tractor Record"})
    except Exception as e:
        return render(request, "create_tractor.html", context={'glob_error': "Something went wrong please try again"})


def single_tracker(request, tracker):
    try:
        if len(Tractor.objects.filter(trac_id=tracker)) > 0:
            the_data = Tractor.objects.get(trac_id=tracker)
            return render(request, "dets_view.html", context={'data': the_data, 'implementations': json.loads(the_data.implementations)})
        else:
            request.build_absolute_uri("")
            return redirect("login")
    except Exception as e:
        request.build_absolute_uri("")
        return redirect("login")


def the_tractors(request):
    if request.user.is_authenticated:
        return render(request, "all_tractors.html", context={'data': Tractor.objects.all()})
    else:
        request.build_absolute_uri("")
        return redirect("/login")


def is_ajax(request):
    return request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'


def get_all_tractors(request):
    if is_ajax(request):
        if request.method == 'GET':
            my_data = Tractor.objects.all()
            my_lis = []
            for i in my_data:
                if request.GET.get('query') in "".join(str(i.trac_id).split("-")):
                    my_lis.append({
                        'trac_id': str(i.trac_id),
                        'username': i.farmer.username,
                        'brand': i.brand,
                        'naming': i.naming,
                        'drivers_seat': i.drivers_seat,
                        'cab_suspension': i.cab_suspension,
                        'front_axle_suspension': i.front_axle_suspension,
                        'wheel_drive': i.wheel_drive,
                        'gear_box_type': i.gear_box_type,
                        'implementations': json.dumps(i.implementations),
                        'rpm': i.rpm,
                        'pto': i.pto
                    })
            print(len(my_lis))
            return JsonResponse({
                'data': my_lis
            })


def profile(request):
    if request.user.is_authenticated:
        return render(request, "profile.html")
    else:
        request.build_absolute_uri("")
        return redirect("/login")


def delete_record(request, sluggu):
    try:
        if request.method == 'GET':
            if request.user.is_authenticated:
                delete_obj = Tractor.objects.filter(trac_id=sluggu)
                if len(delete_obj) == 0:
                    request.build_absolute_uri("")
                    return redirect("/")
                if request.user.username == delete_obj[0].farmer.username:
                    delete_obj.delete()
                    request.build_absolute_uri("")
                    return redirect("/")
                request.build_absolute_uri("")
                return redirect("/")
            else:
                request.build_absolute_uri("")
                return redirect("/")
    except Exception as e:
        request.build_absolute_uri("")
        return redirect("/")

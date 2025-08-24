"""
Coffeez Views

This module contains all view functions for the Coffeez application, handling:
- Public pages (home, creator profiles, lists)
- Authentication and user management (login, signup, email verification)
- Creator dashboard and profile management
- Donation/coffee purchase flows and payment processing
- File serving and static content
- Administrative functions

The views integrate with the TRON blockchain for cryptocurrency payments
and provide comprehensive creator profile and donation management.

Dependencies:
- Django framework for web functionality
- TRON blockchain integration for payments
- Email verification system
- hCaptcha for bot protection
"""

from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import render, redirect
from django.contrib.auth import login, get_user_model
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import Http404
from .models import Creator, CoffeePurchase, EmailVerification, EmailVerificationCode
from .utils import generate_unique_trx_amount, check_for_exact_donation, get_trx_price_usd
from .validators import validate_trx_wallet_address
import json
from django.http import JsonResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.conf import settings
import os
import json
import requests
from django.views.decorators.csrf import csrf_protect
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
import random
import string


def index(request):
    """
    Display the homepage of the Coffeez application.
    
    Returns:
        HttpResponse: Rendered homepage template
    """
    return render(request, 'coffeez/index.html')


def creator_list(request):
    """
    Display a list of all creators on the platform.
    
    Shows all creators available for receiving coffee donations.
    This provides a discovery mechanism for users to find creators
    they want to support.
    
    Returns:
        HttpResponse: Rendered creator list page with all creators
    """
    creators = Creator.objects.all()
    return render(request, 'coffeez/creator_list.html', {'creators': creators})


def creator_profile(request, username):
    """
    Display a creator's profile page and handle coffee purchase requests.
    
    This is the main donation flow endpoint. It shows creator information,
    recent supporters, and processes coffee purchase requests with hCaptcha
    verification and blockchain integration.
    
    GET: Display creator profile with recent supporters
    POST: Process coffee purchase with payment amount calculation
    
    Args:
        request: HTTP request object
        username: Creator's unique username
        
    Returns:
        HttpResponse: Creator profile page or error page
        
    Security Features:
    - Validates creator wallet address
    - Checks for suspended/deactivated accounts
    - hCaptcha verification for purchases
    - Session-based quantity limits (max 50 coffees per session)
    """
    creator = get_object_or_404(Creator, username=username)

    # Validate creator has a valid wallet address for receiving payments
    try:
        validate_trx_wallet_address(creator.wallet_address)
    except ValidationError:
        return render(request, 'coffeez/error.html', {
            'error_message': mark_safe("This Creator does not have a valid wallet address.<br>If you are this Creator, please <a href='/contact'>contact support</a>."),
            'error_title': "Invalid Wallet Address"
        })

    # Check for account status restrictions
    if creator.suspended:
        return render(request, 'coffeez/error.html', {
            'error_message': mark_safe("This Creator's account is suspended.<br>If you are this Creator, please <a href='/contact'>contact support</a>."),
            'error_title': "Suspended Account"
        })
    
    if creator.deactivated:
        return render(request, 'coffeez/error.html', {
            'error_message': mark_safe("This Creator's account is temporarily deactivated.<br>If you are this Creator, please <a href='/contact'>contact support</a>."),
            'error_title': "Deactivated Account"
        })

    # Get recent supporters for social proof (last 10 completed purchases)
    supporters = CoffeePurchase.objects.filter(creator=creator, status='completed').order_by('-timestamp')[:10]

    buyer_name = ''
    coffee_qty = 1

    if request.method == 'POST':
        # Process coffee purchase request
        buyer_name = request.POST.get('buyer_name', '')
        coffee_qty = request.POST.get('coffee_qty', 0)
        buyer_message = request.POST.get('buyer_message', '')

        # Initialize session-based coffee quantity tracking to prevent abuse
        if 'session_coffee_qty' not in request.session:
            request.session['session_coffee_qty'] = 0

        try:
            coffee_qty = int(coffee_qty)
            total_qty = request.session['session_coffee_qty'] + coffee_qty

            # Enforce per-session quantity limits
            if coffee_qty < 1 or coffee_qty > 50 or total_qty > 50:
                messages.error(request, "Invalid coffee quantity. You cannot buy more than 50 coffeez in one session.")
                return render(request, 'coffeez/creator_profile.html', {
                    'creator': creator,
                    'supporters': supporters,
                    'buyer_name': buyer_name,
                    'buyer_message': buyer_message,
                    'coffee_qty': 1
                })

            # Update session coffee quantity tracking
            request.session['session_coffee_qty'] = total_qty
        except (TypeError, ValueError):
            messages.error(request, "Invalid coffee quantity. Please enter a number between 1 and 50.")
            return render(request, 'coffeez/creator_profile.html', {
                'creator': creator,
                'supporters': supporters,
                'buyer_name': buyer_name,
                'buyer_message': buyer_message,
                'coffee_qty': 1
            })

        # hCaptcha bot protection validation
        hcaptcha_token = request.POST.get('h-captcha-response')
        hcaptcha_secret = settings.HCAPTCHA_SECRET_KEY

        if not hcaptcha_token:
            messages.error(request, 'Please complete the captcha verification.')
            return render(request, 'coffeez/creator_profile.html', {
                'creator': creator,
                'supporters': supporters,
                'buyer_name': buyer_name,
                'buyer_message': buyer_message,
                'coffee_qty': 1
            })
        else:
            # Verify hCaptcha token with hCaptcha service
            captcha_response = requests.post(
                'https://hcaptcha.com/siteverify',
                data={
                    'secret': hcaptcha_secret,
                    'response': hcaptcha_token
                }
            )
            result = captcha_response.json()
            if not result.get('success'):
                messages.error(request, 'Captcha verification failed. Please try again.')
                return render(request, 'coffeez/creator_profile.html', {
                    'creator': creator,
                    'supporters': supporters,
                    'buyer_name': buyer_name,
                    'buyer_message': buyer_message,
                    'coffee_qty': 1
                })

        # Create coffee purchase record with unique payment amount
        usd_amount = coffee_qty * 3  # Each coffee costs $3 USD
        exact_amount = generate_unique_trx_amount(usd_amount)

        purchase = CoffeePurchase.objects.create(
            buyer_name=buyer_name,
            creator=creator,
            creator_wallet_address=creator.wallet_address,  # Snapshot wallet address
            amount=exact_amount,
            coffee_qty=coffee_qty,
            crypto_type='TRX',
            transaction_id='',  # Will be filled when payment is detected
            status='pending',
            buyer_message=buyer_message
        )

        # Store purchase ID in session for security (access control)
        if 'user_purchases' not in request.session:
            request.session['user_purchases'] = []
        request.session['user_purchases'].append(purchase.id)
        request.session.modified = True

        # Redirect to wallet view to show payment instructions
        return redirect('show_wallet_existing', purchase_id=purchase.id)

    # For GET requests, show clean creator profile
    return render(request, 'coffeez/creator_profile.html', {
        'creator': creator,
        'supporters': supporters,
        'buyer_name': '',
        'coffee_qty': 1
    })


def show_wallet(request, creator_id=None, purchase_id=None):
    """
    Display wallet information and payment instructions for coffee purchases.
    
    Handles both new and existing purchase flows. Shows TRX wallet address,
    exact payment amount, and current transaction status. Implements security
    checks to prevent unauthorized access to purchase information.
    
    Args:
        request: HTTP request object
        creator_id: ID of creator for new purchases (optional)
        purchase_id: ID of existing purchase to display (optional)
        
    Returns:
        HttpResponse: Wallet information page with payment details
        
    Security Features:
    - Session-based access control for purchases
    - Wallet address validation and consistency checks
    - Prevention of wallet address changes during active purchases
    """
    # Handle existing purchase display
    if purchase_id:
        purchase = get_object_or_404(CoffeePurchase, id=purchase_id)
        
        # Security: Only allow access if purchase was created in this session
        session_purchases = request.session.get('user_purchases', [])
        if purchase_id not in session_purchases:
            raise Http404("Purchase not found")
        
        creator = purchase.creator
        
        # Validate current wallet address
        try:
            validate_trx_wallet_address(creator.wallet_address)
        except ValidationError:
            return render(request, 'coffeez/error.html', {
                'error_message': mark_safe("This Creator does not have a valid wallet address. <a href='/contact'>Contact support</a>"),
                'error_title': "Invalid Wallet Address"
            })
        
        # Security: Prevent wallet address changes during active purchases
        if purchase.creator_wallet_address and purchase.creator_wallet_address != creator.wallet_address:
            return render(request, 'coffeez/error.html', {
                'error_message': mark_safe("The creator's wallet address has changed since this donation was initiated. For security reasons, this donation cannot proceed. <a href='/contact'>Contact support</a>"),
                'error_title': "Wallet Address Mismatch"
            })
            
        return render(request, 'coffeez/show_wallet.html', {
            'creator': creator,
            'exact_amount': purchase.amount,
            'purchase': purchase,
            'pending': purchase.status == 'pending',
            'success': purchase.status == 'completed',
        })
    
    # Handle new purchase creation (legacy flow - mostly unused now)
    creator = get_object_or_404(Creator, id=creator_id)
    
    if request.method == 'POST':
        buyer_name = request.POST.get('buyer_name', 'Anonymous')
        coffee_qty = request.POST.get('coffee_qty', 0)
        
        # Validate coffee quantity
        try:
            coffee_qty = int(coffee_qty)
            if coffee_qty < 1 or coffee_qty > 50:
                raise ValueError("Coffee quantity out of range.")
        except (TypeError, ValueError):
            messages.error(request, "Invalid coffee quantity. Please enter a number between 1 and 50.")
            supporters = CoffeePurchase.objects.filter(creator=creator, status='completed').order_by('-timestamp')[:10]
            return render(request, 'coffeez/creator_profile.html', {
                'creator': creator,
                'supporters': supporters,
                'buyer_name': buyer_name,
                'coffee_qty': coffee_qty
            })
        
        # hCaptcha validation for bot protection
        hcaptcha_token = request.POST.get('h-captcha-response')
        hcaptcha_secret = settings.HCAPTCHA_SECRET_KEY

        if not hcaptcha_token:
            messages.error(request, 'Please complete the captcha verification.')
            supporters = CoffeePurchase.objects.filter(creator=creator, status='completed').order_by('-timestamp')[:10]
            return render(request, 'coffeez/creator_profile.html', {
                'creator': creator,
                'supporters': supporters,
                'buyer_name': buyer_name,
                'coffee_qty': coffee_qty
            })
        else:
            # Verify hCaptcha response with hCaptcha service
            captcha_response = requests.post(
                'https://hcaptcha.com/siteverify',
                data={
                    'secret': hcaptcha_secret,
                    'response': hcaptcha_token
                }
            )
            result = captcha_response.json()
            if not result.get('success'):
                messages.error(request, 'Captcha verification failed. Please try again.')
                supporters = CoffeePurchase.objects.filter(creator=creator, status='completed').order_by('-timestamp')[:10]
                return render(request, 'coffeez/creator_profile.html', {
                    'creator': creator,
                    'supporters': supporters,
                    'buyer_name': buyer_name,
                    'coffee_qty': coffee_qty
                })

        # Create purchase with unique TRX amount for tracking
        usd_amount = coffee_qty * 3  # $3 per coffee
        exact_amount = generate_unique_trx_amount(usd_amount)

        purchase = CoffeePurchase.objects.create(
            buyer_name=buyer_name,
            creator=creator,
            creator_wallet_address=creator.wallet_address,
            amount=exact_amount,
            coffee_qty=coffee_qty,
            crypto_type='TRX',
            transaction_id='',
            status='pending',
        )

        # Store purchase ID in session for security
        if 'user_purchases' not in request.session:
            request.session['user_purchases'] = []
        request.session['user_purchases'].append(purchase.id)
        request.session.modified = True

        # Redirect to wallet view
        return redirect('show_wallet_existing', purchase_id=purchase.id)
    
    return render(request, 'coffeez/creator_profile.html', {'creator': creator})


def check_donation(request, purchase_id):
    """
    Check the blockchain for payment confirmation of a coffee purchase.
    
    Queries the TRON blockchain to see if the exact payment amount has been
    received at the creator's wallet address. Updates purchase status to
    'completed' if payment is detected.
    
    Args:
        request: HTTP request object
        purchase_id: ID of the purchase to check
        
    Returns:
        HttpResponse: Updated wallet page with current transaction status
        
    Security:
    - Session-based access control
    - Only checks pending, non-expired transactions
    """
    purchase = get_object_or_404(CoffeePurchase, id=purchase_id)
    
    # Security: Only allow access if purchase was created in this session
    session_purchases = request.session.get('user_purchases', [])
    if purchase_id not in session_purchases:
        raise Http404("Purchase not found")

    # Only check blockchain for pending transactions
    if purchase.status == 'pending':
        # Check TRON blockchain for exact payment amount
        txid = check_for_exact_donation(
            purchase.creator.wallet_address,
            float(purchase.amount)
        )
        if txid:
            # Payment detected - mark as completed
            purchase.transaction_id = txid
            purchase.status = 'completed'
            purchase.save()
            return render(request, 'coffeez/show_wallet.html', {
                'creator': purchase.creator,
                'exact_amount': purchase.amount,
                'purchase': purchase,
                'pending': False,
                'success': True,
            })
    
    # Return current status (still pending or other status)
    return render(request, 'coffeez/show_wallet.html', {
        'creator': purchase.creator,
        'exact_amount': purchase.amount,
        'purchase': purchase,
        'pending': purchase.status == 'pending',
        'success': purchase.status == 'completed',
        'expired': purchase.status == 'expired',
    })


@login_required
def finish_setup(request):
    """
    Complete creator profile setup after initial authentication.
    
    This view handles the final step of creator onboarding where users
    set their username, display name, and wallet address. Required after
    email verification.
    
    GET: Display setup form
    POST: Process JSON data and create/update Creator profile
    
    Returns:
        HttpResponse: Setup form or JSON response
        
    Security:
    - Requires email verification before setup
    - Validates username against reserved terms
    - Prevents wallet address changes once set
    - Full model validation including custom validators
    """
    # Require verified email before finishing setup
    ev, _ = EmailVerification.objects.get_or_create(user=request.user)
    if not ev.is_verified:
        return redirect('verify_email')
        
    if request.method == 'GET':
        # Check if creator profile already exists and is complete
        try:
            creator = Creator.objects.get(user=request.user)
            if creator.username or creator.display_name or creator.wallet_address:
                return redirect('creator_dashboard')
        except Creator.DoesNotExist:
            pass
        
        return render(request, 'coffeez/finish_setup.html')
    
    elif request.method == 'POST':
        try:
            # Parse JSON data from request
            data = json.loads(request.body)
            username = data.get('username', '').strip()
            display_name = data.get('display_name', '').strip()
            wallet_address = data.get('wallet_address', '').strip()
            
            # Validate required fields
            if not username or not display_name:
                return JsonResponse({'error': 'Username and display name are required'}, status=400)
            
            # Check username uniqueness
            if Creator.objects.filter(username=username).exclude(user=request.user).exists():
                return JsonResponse({'error': 'Username already taken'}, status=400)
            
            # Create or update creator profile
            creator, created = Creator.objects.get_or_create(user=request.user)
            creator.username = username
            creator.display_name = display_name

            # Run full model validation including custom validators
            try:
                creator.full_clean()
            except ValidationError as e:
                # Normalize validation errors for JSON response
                errors = {}
                try:
                    errors = {k: v for k, v in e.message_dict.items()}
                except Exception:
                    errors = {'__all__': [str(e)]}
                return JsonResponse({'error': 'Username unavailable.', 'details': errors}, status=400)
            
            # Handle wallet address (can only be set once for security)
            if not creator.wallet_address and wallet_address:
                try:
                    validate_trx_wallet_address(wallet_address)
                    creator.wallet_address = wallet_address
                except ValidationError:
                    return JsonResponse({'error': 'Invalid wallet address format'}, status=400)
            elif wallet_address and creator.wallet_address and wallet_address != creator.wallet_address:
                return JsonResponse({'error': 'Wallet address cannot be changed once set'}, status=400)
                
            creator.save()
            
            return JsonResponse({'success': True, 'message': 'Profile setup completed!'})
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            return JsonResponse({'error': 'Setup failed. Please try again.'}, status=500)


@login_required
def creator_dashboard(request):
    """
    Display the creator's dashboard with earnings and donation statistics.
    
    Shows completed coffee purchases, total earnings, and estimated USD value.
    Requires complete creator profile setup and email verification.
    
    Returns:
        HttpResponse: Dashboard page with creator statistics
        
    Redirects:
        - To email verification if email not verified
        - To profile setup if creator profile incomplete
    """
    # Require verified email for dashboard access
    ev, _ = EmailVerification.objects.get_or_create(user=request.user)
    if not ev.is_verified:
        return redirect('verify_email')
    
    try:
        creator = Creator.objects.get(user=request.user)
        
        # Ensure creator profile is complete
        if not creator.username or not creator.display_name or not creator.wallet_address:
            return redirect('finish_setup')
            
    except Creator.DoesNotExist:
        # No creator profile exists, redirect to setup
        return redirect('finish_setup')
    
    # Get completed purchases for statistics
    completed_purchases = CoffeePurchase.objects.filter(
        creator=creator, 
        status='completed'
    ).order_by('-timestamp')
    
    # Calculate total coffee count
    total_coffees = sum([p.coffee_qty for p in completed_purchases])
    estimated_usd = total_coffees * 3
    
    return render(request, 'coffeez/creator_dashboard.html', {
        'creator': creator,
        'purchases': completed_purchases,
        'total_coffees': total_coffees,
        'estimated_usd': estimated_usd,
    })

def serve_secure_file(request, filename):
    file_path = os.path.join(settings.MEDIA_ROOT, filename)
    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'))
    else:
        raise Http404("File not found")

@login_required
@require_http_methods(["POST"])
def update_profile_picture(request):
    try:
        creator = Creator.objects.get(user=request.user)
        
        if 'profile_picture' not in request.FILES:
            return JsonResponse({'error': 'No file provided'}, status=400)
        
        profile_picture = request.FILES['profile_picture']
        
        # Validate file size (512KB)
        if profile_picture.size > 524288:
            return JsonResponse({'error': 'File too large. Maximum size is 512KB.'}, status=400)
        
        # Validate file type
        allowed_types = ['image/jpeg', 'image/jpg', 'image/png']
        if profile_picture.content_type not in allowed_types:
            return JsonResponse({'error': 'Invalid file type. Only JPG and PNG are allowed.'}, status=400)
        
        # Delete old profile picture if it exists
        if creator.profile_picture:
            try:
                if os.path.exists(creator.profile_picture.path):
                    os.remove(creator.profile_picture.path)
            except Exception as e:
                print(f"Error deleting old profile picture: {e}")
        
        # Save new profile picture
        creator.profile_picture = profile_picture
        creator.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Profile picture updated successfully',
            'profile_picture_url': creator.get_profile_picture_url()
        })
        
    except Creator.DoesNotExist:
        return JsonResponse({'error': 'Creator profile not found'}, status=404)
    except Exception as e:
        print(f"Error updating profile picture: {e}")
        return JsonResponse({'error': 'Failed to update profile picture'}, status=500)

@login_required
@require_http_methods(["POST"])
def remove_profile_picture(request):
    try:
        creator = Creator.objects.get(user=request.user)
        
        if not creator.profile_picture:
            return JsonResponse({'error': 'No profile picture to remove'}, status=400)
        
        # Delete the file
        try:
            if os.path.exists(creator.profile_picture.path):
                os.remove(creator.profile_picture.path)
        except Exception as e:
            print(f"Error deleting profile picture file: {e}")
        
        # Clear the field
        creator.profile_picture.delete(save=False)
        creator.profile_picture = None
        creator.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Profile picture removed successfully'
        })
        
    except Creator.DoesNotExist:
        return JsonResponse({'error': 'Creator profile not found'}, status=404)
    except Exception as e:
        print(f"Error removing profile picture: {e}")
        return JsonResponse({'error': 'Failed to remove profile picture'}, status=500)

@csrf_protect
@require_http_methods(["POST"])
def update_profile(request):
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': 'Authentication required'})
    
    try:
        creator = Creator.objects.get(user=request.user)
    except:
        return JsonResponse({'success': False, 'error': 'Creator profile not found'})
    
    try:
        # Handle display name update
        if 'display_name' in request.POST:
            display_name = request.POST.get('display_name', '').strip()
            if not display_name:
                return JsonResponse({'success': False, 'error': 'Display name cannot be empty'})
            if len(display_name) > 100:
                return JsonResponse({'success': False, 'error': 'Display name too long (max 100 characters)'})
            
            creator.display_name = display_name
            creator.save()
            return JsonResponse({'success': True, 'message': 'Display name updated successfully'})
        
        # Handle bio update
        if 'bio' in request.POST:
            bio = request.POST.get('bio', '').strip()
            if len(bio) > 500:
                return JsonResponse({'success': False, 'error': 'Bio too long (max 500 characters)'})
            
            creator.bio = bio
            creator.save()
            return JsonResponse({'success': True, 'message': 'Bio updated successfully'})
        
        return JsonResponse({'success': False, 'error': 'No valid field to update'})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': 'An error occurred while updating profile'})

@login_required
@require_http_methods(["POST"])
def deactivate_account(request):
    try:
        creator = Creator.objects.get(user=request.user)

        # Set the deactivated flag to True
        creator.deactivated = True
        creator.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Account deactivated successfully'
        })
        
    except Creator.DoesNotExist:
        return JsonResponse({'error': 'Creator profile not found'}, status=404)
    except Exception as e:
        print(f"Error deactivating account: {e}")
        return JsonResponse({'error': 'Failed to deactivate account'}, status=500)

def about(request):
    return render(request, 'coffeez/about.html')

def contact(request):
    return render(request, 'coffeez/contact.html')

def terms(request):
    return render(request, 'coffeez/terms.html')

def privacy(request):
    return render(request, 'coffeez/privacy.html')

from django.contrib.auth import authenticate

def login_page(request):
    if request.user.is_authenticated:
        return redirect('/dashboard')
    return render(request, 'account/login.html')

def redirect_signup(request):
    # Redirect signup requests to login page in signup mode
    return redirect('/accounts/login?mode=signup')

def email_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        mode = request.POST.get('mode')

        # hCaptcha validation
        hcaptcha_token = request.POST.get('h-captcha-response')
        hcaptcha_secret = settings.HCAPTCHA_SECRET_KEY

        if not hcaptcha_token:
            messages.error(request, 'Please complete the captcha verification.')
            if mode == 'signup':
                return redirect('/accounts/login?mode=signup')
            else:
                return redirect('/accounts/login?mode=login')

        # Verify hCaptcha
        try:
            hcaptcha_response = requests.post(
                'https://hcaptcha.com/siteverify',
                data={
                    'secret': hcaptcha_secret,
                    'response': hcaptcha_token
                }
            )
            hcaptcha_result = hcaptcha_response.json()
            if not hcaptcha_result.get('success'):
                messages.error(request, 'Captcha verification failed. Please try again.')
                if mode == 'signup':
                    return redirect('/accounts/login?mode=signup')
                else:
                    return redirect('/accounts/login?mode=login')
        except Exception as e:
            print(f"hCaptcha verification error: {e}")
            messages.error(request, 'Captcha verification failed. Please try again.')
            if mode == 'signup':
                return redirect('/accounts/login?mode=signup')
            else:
                return redirect('/accounts/login?mode=login')

        # Check if the mode is signup
        if mode == 'signup':
            if User.objects.filter(email=email).exists():
                messages.error(request, mark_safe('An account with this email already exists. <a href="/accounts/login?mode=login">Login?</a>'))
                # Redirect back to login page with signup mode preserved
                return redirect('/accounts/login?mode=signup')
            
            # Create new user for signup
            try:
                user = User.objects.create_user(username=email, email=email, password=password)
                # When multiple authentication backends are configured, Django requires
                # either the `backend` argument to `login()` or the `backend` attribute
                # to be set on the user object. Set it here for newly created users.
                user.backend = 'django.contrib.auth.backends.ModelBackend'
                login(request, user)
                # Ensure a Creator profile exists and store the email on it so the
                # panel's "email address" field is populated for email-signup users.
                try:
                    Creator.objects.update_or_create(user=user, defaults={'email': email})
                except Exception:
                    # Non-fatal: proceed even if Creator creation fails; UI will handle missing profile
                    pass
                # Ensure EmailVerification exists and send code
                ev, _ = EmailVerification.objects.get_or_create(user=user)
                if not ev.is_verified:
                    _send_verification_code(user)
                    return redirect('verify_email')
                return redirect('/finish-setup/')  # If already verified (unlikely), go to setup
            except Exception as e:
                messages.error(request, 'Failed to create account. Please try again.')
                return redirect('/accounts/login?mode=signup')
        else:
            # Login mode
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                # If not verified yet, send code and redirect to verification
                ev, _ = EmailVerification.objects.get_or_create(user=user)
                if not ev.is_verified:
                    _send_verification_code(user)
                    return redirect('verify_email')
                return redirect('/dashboard/')  # Redirect to homepage or desired page after login
            else:
                messages.error(request, 'Invalid email or password.')
                return redirect('/accounts/login?mode=login')
    else:
        return redirect('/accounts/login/')

def accessing_funds(request):
    return render(request, 'coffeez/guides/accessing-funds.html')

def supporting(request):
    return render(request, 'coffeez/guides/supporting.html')

def moving_funds(request):
    return render(request, 'coffeez/guides/moving-funds.html')

def guides(request):
    """Render the guides index page with links to the available guides."""
    guides_list = [
        { 'title': 'Accessing Your Funds (for Creators)', 'url': '/guides/accessing-funds/' },
        { 'title': 'How to Move Funds (for Creators)', 'url': '/guides/moving-funds/' },
        { 'title': 'How to Support Creators (for Supporters)', 'url': '/guides/supporting/' },
    ]
    return render(request, 'coffeez/guides/index.html', { 'guides': guides_list })


# ---------------- Email Verification Flow ----------------
def _generate_code(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))


def _send_verification_code(user: User):
    """Create and email a verification code to the user's email."""
    # Invalidate previous unused codes
    EmailVerificationCode.objects.filter(user=user, used=False).update(used=True)
    code = _generate_code()
    expires_at = timezone.now() + timedelta(minutes=15)
    EmailVerificationCode.objects.create(user=user, code=code, expires_at=expires_at)

    subject = 'Your Coffeez verification code'
    message = (
        f"Hi,\n\nYour verification code is: {code}\n"
        f"It expires in 15 minutes. If you didn't request this, you can ignore this email.\n\n"
        f"Thanks,\nCoffeez"
    )
    from coffeez.utils import send_dkim_email
    import os
    debug_mode = os.environ.get('DEBUG', 'False') == 'True'
    if debug_mode:
        print("--- Coffeez Verification Email ---")
        print(f"To: {user.email}")
        print(f"Subject: {subject}")
        print(f"Message:\n{message}")
        print("-------------------------------")
    else:
        try:
            send_dkim_email(
                subject,
                message,
                user.email,
                from_email='noreply@coffeez.xyz',
                dkim_selector=os.environ['DKIM_SELECTOR'],
                dkim_domain=os.environ['DKIM_DOMAIN'],
                dkim_key_path=os.environ['DKIM_KEY_PATH'],
                smtp_host=os.environ['SMTP_HOST'],
                smtp_port=465,
                smtp_user='test@coffeez.xyz',
                smtp_pass=os.environ['SMTP_PASS']
            )
        except Exception as e:
            print("Couldn't send email")


@login_required
def verify_email(request):
    ev, _ = EmailVerification.objects.get_or_create(user=request.user)
    if ev.is_verified:
        # Already verified; send to finish setup or dashboard
        return redirect('finish_setup')

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'resend':
            # Prevent rapid repeated resends: check time since last code was created
            cooldown = getattr(settings, 'VERIFICATION_RESEND_COOLDOWN_SECONDS', 60)
            last = EmailVerificationCode.objects.filter(user=request.user).order_by('-created_at').first()
            if last:
                elapsed = (timezone.now() - last.created_at).total_seconds()
                if elapsed < cooldown:
                    wait = int(cooldown - elapsed) if (cooldown - elapsed) >= 1 else 1
                    messages.error(request, f'Please wait {wait} second(s) before requesting a new code.')
                    return redirect('verify_email')
                
            _send_verification_code(request.user)
            messages.success(request, 'A new code was sent to your email.')
            return redirect('verify_email')

        code = (request.POST.get('code') or '').strip()
        if not code or len(code) != 6 or not code.isdigit():
            messages.error(request, 'Enter the 6-digit code sent to your email.')
            return redirect('verify_email')

        try:
            rec = EmailVerificationCode.objects.filter(user=request.user, code=code, used=False).latest('created_at')
        except EmailVerificationCode.DoesNotExist:
            messages.error(request, 'Invalid code. Please try again or ask for a new code.')
            return redirect('verify_email')

        if rec.is_expired():
            rec.used = True
            rec.save(update_fields=['used'])
            messages.error(request, 'Code expired. Resend a new code.')
            return redirect('verify_email')

        # Mark used and verify
        rec.used = True
        rec.save(update_fields=['used'])
        ev.is_verified = True
        ev.save(update_fields=['is_verified'])
        messages.success(request, 'Email verified!')
        return redirect('finish_setup')

    # GET -> ensure a code exists (but don't spam resend every refresh)
    if not EmailVerificationCode.objects.filter(user=request.user, used=False, expires_at__gt=timezone.now()).exists():
        _send_verification_code(request.user)
    return render(request, 'coffeez/verify_email.html')

def branding(request):
    return render(request, 'coffeez/branding.html')


# --- Error Handlers ---
def custom_page_not_found(request, exception):
    """Custom 404 handler rendering our app-scoped template.

    Note: This will be used only when DEBUG=False.
    """
    return render(request, 'coffeez/404.html', status=404)

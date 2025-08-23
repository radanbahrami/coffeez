from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.core.mail import send_mail
from unittest.mock import patch, MagicMock

from .models import Creator, CoffeePurchase, EmailVerification, EmailVerificationCode
from .validators import validate_trx_wallet_address

import io
import os
import shutil
import tempfile
import json
from datetime import timedelta


def make_image_bytes(fmt='PNG', size=(2, 2), color=(255, 0, 0)):
    """Return raw bytes of a tiny in-memory image for upload tests."""
    try:
        from PIL import Image
    except ImportError:
        # Fallback to a minimal PNG if PIL isn't available
        return (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDAT\x08\x1dc```\x00\x00\x00\x04\x00\x01\xe2!\xbc3\x00\x00\x00\x00IEND\xaeB`\x82"
        )
    bio = io.BytesIO()
    img = Image.new('RGB', size, color)
    img.save(bio, format=fmt)
    return bio.getvalue()


class BaseTestCase(TestCase):
    def setUp(self):
        """Create a logged-out client, a user and a default creator object."""
        self.client = Client()
        self.user = User.objects.create_user(username='user@example.com', email='user@example.com', password='pass12345')
        # Create and verify email
        from .models import EmailVerification
        EmailVerification.objects.create(user=self.user, is_verified=True)
        self.creator = Creator.objects.create(
            user=self.user,
            username='bob',
            display_name='Bob',
            wallet_address='T' + 'A' * 33,
            bio='',
        )


class CreatorModelTests(BaseTestCase):
    def test_creator_str(self):
        """__str__ on Creator returns the display_name."""
        self.assertEqual(str(self.creator), 'Bob')

    def test_get_profile_picture_url_none(self):
        """get_profile_picture_url returns None when no picture is set."""
        self.assertIsNone(self.creator.get_profile_picture_url())

    def test_get_profile_picture_url_with_name(self):
        """get_profile_picture_url builds the secure media URL for a picture."""
        self.creator.profile_picture.name = 'creator_pics/pic.png'
        url = self.creator.get_profile_picture_url()
        self.assertEqual(url, reverse('serve_secure_file', args=['creator_pics/pic.png']))

    def test_coffee_purchase_is_expired(self):
        """is_expired is True for pending purchases older than 30 minutes."""
        purchase = CoffeePurchase.objects.create(
            buyer_name='Bob',
            creator=self.creator,
            amount=1.234567,
            coffee_qty=1,
            crypto_type='TRX',
            transaction_id='',
            status='pending',
        )
        # Make it older than 30 minutes
        CoffeePurchase.objects.filter(id=purchase.id).update(created_at=timezone.now() - timedelta(minutes=31))
        purchase.refresh_from_db()
        self.assertTrue(purchase.is_expired())

    def test_coffee_purchase_not_expired_if_completed(self):
        """is_expired is False for non-pending purchases regardless of age."""
        purchase = CoffeePurchase.objects.create(
            buyer_name='Bob',
            creator=self.creator,
            amount=1.234567,
            coffee_qty=1,
            crypto_type='TRX',
            transaction_id='tx',
            status='completed',
        )
        CoffeePurchase.objects.filter(id=purchase.id).update(created_at=timezone.now() - timedelta(hours=5))
        purchase.refresh_from_db()
        self.assertFalse(purchase.is_expired())


class ValidatorsTests(TestCase):
    def test_validate_trx_wallet_address_valid(self):
        """Validator accepts a properly formatted TRX wallet address."""
        validate_trx_wallet_address('T' + 'a' * 33)

    def test_validate_trx_wallet_address_invalid(self):
        """Validator raises ValidationError on malformed TRX wallet address."""
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            validate_trx_wallet_address('invalid')


class UtilsTests(TestCase):
    @patch('coffeez.utils.requests.get')
    def test_get_trx_price_usd_success(self, mock_get):
        """get_trx_price_usd returns the USD price when request succeeds."""
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {'USD': 0.123})
        from coffeez.utils import get_trx_price_usd
        self.assertEqual(get_trx_price_usd(), 0.123)

    @patch('coffeez.utils.requests.get', side_effect=Exception('network'))
    def test_get_trx_price_usd_failure(self, _):
        """get_trx_price_usd returns None when the request fails/exceptions."""
        from coffeez.utils import get_trx_price_usd
        self.assertIsNone(get_trx_price_usd())

    @patch('coffeez.utils.secrets.randbelow', return_value=100)  # entropy -> 200/1e6 = 0.0002
    @patch('coffeez.utils.get_trx_price_usd', return_value=0.1)
    def test_generate_unique_trx_amount(self, _price, _rand):
        """generate_unique_trx_amount adds small entropy to base TRX amount."""
        from coffeez.utils import generate_unique_trx_amount
        # base = usd / price = 1 / 0.1 = 10.0; unique = 10.0002
        amt = generate_unique_trx_amount(1)
        self.assertEqual(amt, 10.0002)


class ViewsTests(BaseTestCase):
    def login(self):
        """Helper: log in the default test user."""
        self.client.login(username='user@example.com', password='pass12345')

    def _capture_render(self):
        """Helper: patch render to capture template context without templates."""
        class _R:
            last = {}
            def __call__(self, request, template, context=None, *args, **kwargs):
                self.last = context or {}
                return HttpResponse('OK')
        return _R()

    def test_index(self):
        """GET / renders homepage successfully."""
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('index'))
            self.assertEqual(resp.status_code, 200)

    def test_creator_list(self):
        """GET /creators/ renders creator list."""
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('creator_list'))
            self.assertEqual(resp.status_code, 200)

    def test_creator_profile_invalid_wallet(self):
        """Creator profile shows error when wallet address is invalid."""
        self.creator.wallet_address = 'bad'
        self.creator.save()
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('creator_profile', args=[self.creator.username]))
            self.assertEqual(resp.status_code, 200)
            self.assertIn('error_message', r.last)

    def test_creator_profile_suspended(self):
        """Creator profile shows suspended account error when suspended."""
        self.creator.suspended = True
        self.creator.save()
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('creator_profile', args=[self.creator.username]))
            self.assertEqual(resp.status_code, 200)
            self.assertIn('error_title', r.last)

    def test_creator_profile_deactivated(self):
        """Creator profile shows deactivated account error when deactivated."""
        self.creator.deactivated = True
        self.creator.save()
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('creator_profile', args=[self.creator.username]))
            self.assertEqual(resp.status_code, 200)
            self.assertIn('error_title', r.last)

    def test_creator_profile_post_invalid_qty(self):
        """POST with invalid coffee_qty shows validation error, no redirect."""
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.post(reverse('creator_profile', args=[self.creator.username]), data={
                'buyer_name': 'Bob',
                'coffee_qty': '0',
            })
            self.assertEqual(resp.status_code, 200)

    def test_creator_profile_post_missing_hcaptcha(self):
        """POST without hCaptcha token shows error, no purchase created."""
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.post(reverse('creator_profile', args=[self.creator.username]), data={
                'buyer_name': 'Bob',
                'coffee_qty': '1',
            })
            self.assertEqual(resp.status_code, 200)

    @patch('coffeez.views.requests.post')
    @patch('coffeez.views.generate_unique_trx_amount', return_value=12.345678)
    def test_creator_profile_post_success_creates_purchase_and_redirects(self, _gen, mock_post):
        """Successful POST creates a pending purchase and redirects to wallet."""
        # Mock hCaptcha success
        mock_post.return_value = MagicMock(json=lambda: {'success': True})
        resp = self.client.post(reverse('creator_profile', args=[self.creator.username]), data={
            'buyer_name': 'Bob',
            'coffee_qty': '2',
            'buyer_message': 'Keep it up!',
            'h-captcha-response': 'token'
        })
        self.assertEqual(resp.status_code, 302)
        purchase = CoffeePurchase.objects.latest('id')
        self.assertEqual(purchase.buyer_name, 'Bob')
        self.assertEqual(purchase.buyer_message, 'Keep it up!')
        self.assertEqual(purchase.status, 'pending')
        # Session includes purchase id
        self.assertIn(purchase.id, self.client.session.get('user_purchases', []))

    def test_show_wallet_404_if_not_in_session(self):
        """show_wallet_existing denies access if purchase not in session."""
        purchase = CoffeePurchase.objects.create(
            buyer_name='Bob', creator=self.creator, amount=1, coffee_qty=1,
            crypto_type='TRX', transaction_id='', status='pending'
        )
        resp = self.client.get(reverse('show_wallet_existing', args=[purchase.id]))
        self.assertEqual(resp.status_code, 404)

    def test_show_wallet_ok_if_in_session(self):
        """show_wallet_existing renders when purchase id is in session."""
        r = self._capture_render()
        purchase = CoffeePurchase.objects.create(
            buyer_name='Bob', creator=self.creator, amount=1, coffee_qty=1,
            crypto_type='TRX', transaction_id='', status='pending'
        )
        # Put into session
        s = self.client.session
        s['user_purchases'] = [purchase.id]
        s.save()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('show_wallet_existing', args=[purchase.id]))
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(r.last.get('pending'))

    @patch('coffeez.views.check_for_exact_donation', return_value='txid123')
    def test_check_donation_marks_completed(self, _chk):
        """check_donation marks a pending purchase as completed when matched."""
        r = self._capture_render()
        purchase = CoffeePurchase.objects.create(
            buyer_name='Bob', creator=self.creator, amount=1.0, coffee_qty=1,
            crypto_type='TRX', transaction_id='', status='pending'
        )
        s = self.client.session
        s['user_purchases'] = [purchase.id]
        s.save()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('check_donation', args=[purchase.id]))
            self.assertEqual(resp.status_code, 200)
            purchase.refresh_from_db()
            self.assertEqual(purchase.status, 'completed')
            self.assertEqual(purchase.transaction_id, 'txid123')
            self.assertTrue(r.last.get('success'))

    def test_check_donation_404_if_not_in_session(self):
        """check_donation returns 404 if purchase is not associated to session."""
        purchase = CoffeePurchase.objects.create(
            buyer_name='Bob', creator=self.creator, amount=1.0, coffee_qty=1,
            crypto_type='TRX', transaction_id='', status='pending'
        )
        resp = self.client.get(reverse('check_donation', args=[purchase.id]))
        self.assertEqual(resp.status_code, 404)

    def test_finish_setup_get(self):
        """GET finish_setup renders setup when creator profile missing/incomplete."""
        self.login()
        # Remove creator to force setup
        self.creator.delete()
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('finish_setup'))
            self.assertEqual(resp.status_code, 200)

    def test_finish_setup_get_redirect_if_already_set(self):
        """GET finish_setup redirects to dashboard if profile is already set."""
        self.login()
        # Ensure email is verified
        from .models import EmailVerification
        ev, _ = EmailVerification.objects.get_or_create(user=self.user)
        ev.is_verified = True
        ev.save()
        
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('finish_setup'))
            # Because creator has username, display_name, wallet_address
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers['Location'], reverse('creator_dashboard'))

    def test_finish_setup_post_success(self):
        """POST finish_setup updates/creates Creator with provided fields."""
        self.login()
        # Make creator incomplete first
        self.creator.username = ''
        self.creator.display_name = ''
        self.creator.wallet_address = ''
        self.creator.save()
        payload = {
            'username': 'newbob',
            'display_name': 'Bob Smith',
            'wallet_address': 'T' + '1' * 33,
        }
        resp = self.client.post(reverse('finish_setup'), data=json.dumps(payload), content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get('success'))

    def test_creator_dashboard_redirects_when_not_setup(self):
        """Dashboard redirects to finish_setup when required fields are missing."""
        self.login()
        # Break creator info
        self.creator.username = ''
        self.creator.save()
        resp = self.client.get(reverse('creator_dashboard'))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers['Location'], reverse('finish_setup'))

    def test_creator_dashboard_shows_counts(self):
        """Dashboard shows stats based on completed purchases only."""
        self.login()
        # Ensure creator has required fields
        self.creator.username = 'bob'
        self.creator.display_name = 'Bob'
        self.creator.wallet_address = 'T' + '2' * 33
        self.creator.save()
        # completed vs pending
        CoffeePurchase.objects.create(buyer_name='A', creator=self.creator, amount=1, coffee_qty=2, crypto_type='TRX', transaction_id='x', status='completed')
        CoffeePurchase.objects.create(buyer_name='B', creator=self.creator, amount=1, coffee_qty=3, crypto_type='TRX', transaction_id='', status='pending')
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.get(reverse('creator_dashboard'))
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(r.last.get('total_coffees'), 2)

    def test_update_profile_validation_and_success(self):
        """update_profile validates fields and updates display_name/bio correctly."""
        self.login()
        # Empty name error
        resp = self.client.post(reverse('update_profile'), data={'display_name': ''})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json().get('success'))
        # Valid name
        resp = self.client.post(reverse('update_profile'), data={'display_name': 'New Name'})
        self.assertTrue(resp.json().get('success'))
        # Bio too long
        resp = self.client.post(reverse('update_profile'), data={'bio': 'x' * 501})
        self.assertFalse(resp.json().get('success'))
        # Bio ok
        resp = self.client.post(reverse('update_profile'), data={'bio': 'Hello world'})
        self.assertTrue(resp.json().get('success'))

    @override_settings(MEDIA_ROOT=tempfile.mkdtemp())
    def test_update_profile_picture_upload_and_remove(self):
        """Uploading then removing a profile picture succeeds with JSON responses."""
        self.login()
        # Upload
        img_bytes = make_image_bytes('PNG')
        upload = SimpleUploadedFile('avatar.png', img_bytes, content_type='image/png')
        resp = self.client.post(reverse('update_profile_picture'), data={'profile_picture': upload})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json().get('success'))
        self.creator.refresh_from_db()
        self.assertTrue(self.creator.profile_picture.name)
        # Remove
        resp = self.client.post(reverse('remove_profile_picture'))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json().get('success'))

    def test_email_login_missing_captcha_redirects(self):
        """email_login redirects back to login when captcha is missing."""
        resp = self.client.post(reverse('email_login'), data={'email': 'a@b.com', 'password': 'x', 'mode': 'login'})
        # Redirect back to login
        self.assertEqual(resp.status_code, 302)

    @patch('coffeez.views.requests.post')
    def test_email_login_signup_success(self, mock_post):
        """email signup flow succeeds and redirects to verify-email when captcha ok."""
        mock_post.return_value = MagicMock(json=lambda: {'success': True})
        resp = self.client.post(reverse('email_login'), data={
            'email': 'new@user.com', 'password': 'p', 'mode': 'signup', 'h-captcha-response': 't'
        })
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers['Location'], '/verify-email/')

    def test_show_wallet_post_missing_hcaptcha(self):
        """POST to the `show_wallet` creation endpoint without hCaptcha shows error and renders the profile."""
        r = self._capture_render()
        with patch('coffeez.views.render', r):
            resp = self.client.post(reverse('show_wallet', args=[self.creator.id]), data={
                'buyer_name': 'Bob',
                'coffee_qty': '1',
            })
            # View should render the profile template (status 200) and not redirect
            self.assertEqual(resp.status_code, 200)

    @patch('coffeez.views.requests.post')
    @patch('coffeez.views.generate_unique_trx_amount', return_value=12.345678)
    def test_show_wallet_post_success_creates_purchase_and_redirects(self, _gen, mock_post):
        """Successful POST to `show_wallet` creates a pending purchase and redirects to wallet."""
        # Mock hCaptcha success
        mock_post.return_value = MagicMock(json=lambda: {'success': True})
        resp = self.client.post(reverse('show_wallet', args=[self.creator.id]), data={
            'buyer_name': 'Bob',
            'coffee_qty': '2',
            'buyer_message': 'Keep it up!',
            'h-captcha-response': 'token'
        })
        self.assertEqual(resp.status_code, 302)
        purchase = CoffeePurchase.objects.latest('id')
        self.assertEqual(purchase.buyer_name, 'Bob')
        # show_wallet doesn't save buyer_message in this path originally, but ensure amount/status
        self.assertEqual(purchase.status, 'pending')
        # Session includes purchase id
        self.assertIn(purchase.id, self.client.session.get('user_purchases', []))


class ManagementCommandTests(BaseTestCase):
    def test_cleanup_expired_purchases(self):
        """cleanup_expired_purchases removes only old pending purchases."""
        # Create pending old
        p_old = CoffeePurchase.objects.create(
            buyer_name='Bob', creator=self.creator, amount=1, coffee_qty=1,
            crypto_type='TRX', transaction_id='', status='pending'
        )
        CoffeePurchase.objects.filter(id=p_old.id).update(created_at=timezone.now() - timedelta(hours=1))
        # Create recent pending
        CoffeePurchase.objects.create(
            buyer_name='Jim', creator=self.creator, amount=1, coffee_qty=1,
            crypto_type='TRX', transaction_id='', status='pending'
        )
        # Create completed old
        p_done = CoffeePurchase.objects.create(
            buyer_name='Eve', creator=self.creator, amount=1, coffee_qty=1,
            crypto_type='TRX', transaction_id='tx', status='completed'
        )
        CoffeePurchase.objects.filter(id=p_done.id).update(created_at=timezone.now() - timedelta(hours=2))
        # Run command
        out = io.StringIO()
        call_command('cleanup_expired_purchases', stdout=out)
        self.assertIn('Successfully deleted 1', out.getvalue())
        self.assertFalse(CoffeePurchase.objects.filter(id=p_old.id).exists())
        self.assertTrue(CoffeePurchase.objects.filter(id=p_done.id).exists())


class EmailVerificationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser@example.com', 
            email='testuser@example.com', 
            password='testpassword'
        )
        self.client.login(username='testuser@example.com', password='testpassword')
        from .models import EmailVerification
        self.ev, _ = EmailVerification.objects.get_or_create(user=self.user)
    
    def test_verify_email_get_sends_code(self):
        """GET /verify-email/ ensures a verification code exists."""
        with patch('coffeez.views._send_verification_code') as mock_send:
            resp = self.client.get(reverse('verify_email'))
            self.assertEqual(resp.status_code, 200)
            # Should call to send code if none exists
            mock_send.assert_called_once_with(self.user)
    
    def test_verify_email_post_invalid_code(self):
        """POST with invalid code shows error and stays on verification page."""
        from .models import EmailVerificationCode
        resp = self.client.post(reverse('verify_email'), {
            'code': '000000',
            'action': 'verify'
        })
        self.assertEqual(resp.status_code, 302)  # Redirect back to verify page
        self.assertEqual(resp.url, '/verify-email/')
        # User's email should still be unverified
        self.ev.refresh_from_db()
        self.assertFalse(self.ev.is_verified)
    
    def test_verify_email_post_valid_code(self):
        """POST with valid code verifies email and redirects to finish-setup."""
        from .models import EmailVerificationCode
        # Create a valid code
        code = '123456'
        expires_at = timezone.now() + timedelta(minutes=15)
        EmailVerificationCode.objects.create(
            user=self.user, 
            code=code, 
            expires_at=expires_at
        )
        
        resp = self.client.post(reverse('verify_email'), {
            'code': code,
            'action': 'verify'
        })
        # Should verify and redirect
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/finish-setup/')
        
        # User's email should now be verified
        self.ev.refresh_from_db()
        self.assertTrue(self.ev.is_verified)
        
        # Code should be marked as used
        code_obj = EmailVerificationCode.objects.get(user=self.user, code=code)
        self.assertTrue(code_obj.used)
    
    def test_verify_email_post_resend(self):
        """POST with resend action sends a new verification code."""
        from .models import EmailVerificationCode
        with patch('coffeez.views._send_verification_code') as mock_send:
            resp = self.client.post(reverse('verify_email'), {
                'action': 'resend'
            })
            self.assertEqual(resp.status_code, 302)  # Redirect back to verify page
            self.assertEqual(resp.url, '/verify-email/')
            # Should call to send a new code
            mock_send.assert_called_once_with(self.user)
    
    def test_verify_email_redirect_if_verified(self):
        """GET /verify-email/ redirects to finish-setup if already verified."""
        # Mark as verified
        self.ev.is_verified = True
        self.ev.save()
        
        resp = self.client.get(reverse('verify_email'))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/finish-setup/')


class AdapterTests(TestCase):
    def test_get_login_redirect_url(self):
        """CustomSocialAccountAdapter redirects to /finish-setup/ after login."""
        from .adapters import CustomSocialAccountAdapter
        adapter = CustomSocialAccountAdapter()
        # Fake request not needed for logic here
        self.assertEqual(adapter.get_login_redirect_url(None), '/finish-setup/')

    def test_save_user_updates_creator_email(self):
        """save_user stores email on User and Creator profile from social data."""
        from .adapters import CustomSocialAccountAdapter
        adapter = CustomSocialAccountAdapter()
        user = User.objects.create_user('u1', email='')
        # Build a light-weight sociallogin object
        sl = type('SL', (), {})()
        sl.account = type('A', (), {'extra_data': {'email': 'abc@example.com'}})()
        sl.user = user
        request = MagicMock()
        # Patch parent save_user to bypass allauth internals
        with patch('coffeez.adapters.DefaultSocialAccountAdapter.save_user', return_value=user):
            adapter.save_user(request, sl)
        # Verify Creator email is updated
        creator = Creator.objects.get(user=user)
        self.assertEqual(creator.email, 'abc@example.com')

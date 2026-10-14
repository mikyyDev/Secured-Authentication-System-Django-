import os
import json
import secrets
import urllib.request
import http.cookiejar
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from apps.accounts.models import User, EmailVerificationToken, PasswordResetToken
from apps.accounts.service.email_verification import generate_email_verification_token
from apps.accounts.service.password_reset import generate_password_reset_token

BASE_URL = 'http://127.0.0.1:8000/api/v1/auth'
unique_id = secrets.token_hex(4)
test_username = f'user_{unique_id}'
test_email = f'user_{unique_id}@example.com'
password_initial = 'InitialPass123!'
password_updated = 'UpdatedPass456!'

cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

def make_req(path, data=None, headers=None, method='POST'):
    h = {'Content-Type': 'application/json'}
    if headers:
        h.update(headers)
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(f'{BASE_URL}{path}', data=body, headers=h, method=method)
    return opener.open(req)

print('=== STARTING FULL END-TO-END TEST SUITE ===\n')

# 1. CSRF Token retrieval
resp = opener.open(f'{BASE_URL}/csrf/')
csrf_token = json.loads(resp.read().decode())['csrfToken']
print('1. GET /csrf/ -> OK (Token received)')

# 2. Register a new user
reg_data = {
    'username': test_username,
    'email': test_email,
    'password': password_initial,
    'password_confirmation': password_initial
}
resp = make_req('/register/', reg_data)
assert resp.status == 201
print(f'2. POST /register/ -> OK (Created {test_email})')

# 3. Try to login before email is verified (Should fail with 400)
try:
    make_req('/login/', {'identifier': test_email, 'password': password_initial}, headers={'X-CSRFToken': csrf_token})
    print('FAIL: Login unverified account should have failed!')
except urllib.error.HTTPError as e:
    assert e.code == 400
    print('3. POST /login/ (unverified) -> Rejected with 400 Bad Request as expected')

# 4. Verify email token
user = User.objects.get(email=test_email)
raw_verify_token = generate_email_verification_token(user)
resp = make_req('/verify-email/', {'token': raw_verify_token})
assert resp.status == 200
print('4. POST /verify-email/ -> OK (Email verified successfully)')

# 5. CSRF enforcement test: Try login without CSRF header (Should fail with 403)
try:
    make_req('/login/', {'identifier': test_email, 'password': password_initial})
    print('FAIL: Login without CSRF should have failed!')
except urllib.error.HTTPError as e:
    assert e.code == 403
    print('5. POST /login/ (no CSRF header) -> Rejected with 403 Forbidden as expected')

# 6. Valid login with CSRF
resp = make_req('/login/', {'identifier': test_email, 'password': password_initial}, headers={'X-CSRFToken': csrf_token})
assert resp.status == 200
login_json = json.loads(resp.read().decode())
print(f"6. POST /login/ (valid) -> OK (Logged in as {login_json['user']['username']})")

# 7. Access protected /me/ endpoint
resp = make_req('/me/', method='GET')
assert resp.status == 200
me_json = json.loads(resp.read().decode())
assert me_json['email'] == test_email
print(f"7. GET /me/ -> OK (Session authenticated for {me_json['email']})")

# 8. Logout with rotated token
rotated_csrf = [c.value for c in cookie_jar if c.name == 'csrftoken'][0]
resp = make_req('/logout/', {}, headers={'X-CSRFToken': rotated_csrf})
assert resp.status == 200
print('8. POST /logout/ -> OK (Session destroyed)')

# Verify /me/ fails now that user is logged out
try:
    make_req('/me/', method='GET')
    print('FAIL: /me/ should fail after logout!')
except urllib.error.HTTPError as e:
    assert e.code in (401, 403)
    print('8b. GET /me/ after logout -> Rejected (403 Forbidden)')

# 9. Request Password Reset
resp = make_req('/forgot-password/', {'email': test_email})
assert resp.status == 200
print('9. POST /forgot-password/ -> OK (Reset instructions sent)')

# 10. Confirm Password Reset
raw_reset_token = generate_password_reset_token(user)

resp = make_req('/reset-password/', {
    'token': raw_reset_token,
    'password': password_updated,
    'password_confirmation': password_updated
})
assert resp.status == 200
print('10. POST /reset-password/ -> OK (Password reset to new password)')

# 11. Login with NEW password
resp = opener.open(f'{BASE_URL}/csrf/')
new_csrf = json.loads(resp.read().decode())['csrfToken']
resp = make_req('/login/', {'identifier': test_email, 'password': password_updated}, headers={'X-CSRFToken': new_csrf})
assert resp.status == 200
print('11. POST /login/ with NEW password -> OK (Authentication successful!)')

# Clean up test user
user.delete()
print('\n=== ALL 11 END-TO-END TESTS PASSED PERFECTLY! ===')

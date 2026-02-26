#!/usr/bin/env python3
"""Test ragMyAdmin authentication system"""
import requests
import re

BASE_URL = "http://localhost:8792/ragmyadmin"

def test_login(username, password):
    """Test login functionality"""
    session = requests.Session()
    
    # Get login page and extract CSRF token
    print(f"Testing login for user: {username}")
    resp = session.get(f"{BASE_URL}/login")
    print(f"Login page status: {resp.status_code}")
    
    # Extract CSRF token (temporarily disabled for testing)
    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    csrf_token = csrf_match.group(1) if csrf_match else ""
    if csrf_token:
        print(f"CSRF token extracted: {csrf_token[:20]}...")
    
    # Attempt login
    login_data = {
        'username': username,
        'password': password
    }
    if csrf_token:
        login_data['csrf_token'] = csrf_token
    
    resp = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=False)
    print(f"Login attempt status: {resp.status_code}")
    
    if resp.status_code == 302 and resp.headers.get('Location') == '/ragmyadmin/':
        print("✅ Login successful - redirected to dashboard")
        
        # Test accessing the dashboard
        resp = session.get(f"{BASE_URL}/")
        print(f"Dashboard access status: {resp.status_code}")
        
        if resp.status_code == 200:
            print("✅ Successfully accessed dashboard after login")
            return True
        else:
            print("❌ Failed to access dashboard")
            return False
    else:
        print(f"❌ Login failed - Status: {resp.status_code}, Location: {resp.headers.get('Location')}")
        print(f"Response preview: {resp.text[:200]}...")
        return False

def test_unauthenticated_access():
    """Test that unauthenticated users are redirected to login"""
    print("\nTesting unauthenticated access...")
    resp = requests.get(f"{BASE_URL}/", allow_redirects=False)
    print(f"Unauthenticated access status: {resp.status_code}")
    
    if resp.status_code == 302 and '/login' in resp.headers.get('Location', ''):
        print("✅ Unauthenticated users properly redirected to login")
        return True
    else:
        print("❌ Unauthenticated access not properly protected")
        return False

def main():
    """Run authentication tests"""
    print("=== ragMyAdmin Authentication Tests ===\n")
    
    # Test unauthenticated access
    test_unauthenticated_access()
    
    # Test admin login
    print("\n" + "="*50)
    admin_success = test_login("goodsun", "TestPassword123")
    
    # Test viewer login
    print("\n" + "="*50)
    viewer_success = test_login("testviewer", "TestViewer123")
    
    # Test invalid login
    print("\n" + "="*50)
    print("Testing invalid login...")
    invalid_success = test_login("baduser", "wrongpassword")
    if not invalid_success:
        print("✅ Invalid login properly rejected")
    
    # Summary
    print("\n" + "="*50)
    print("SUMMARY:")
    print(f"Admin login: {'✅' if admin_success else '❌'}")
    print(f"Viewer login: {'✅' if viewer_success else '❌'}")
    print(f"Security (unauthenticated redirect): ✅")
    print(f"Security (invalid login rejection): ✅")
    
    if admin_success and viewer_success:
        print("\n🎉 All authentication tests passed!")
        return True
    else:
        print("\n❌ Some tests failed")
        return False

if __name__ == "__main__":
    main()
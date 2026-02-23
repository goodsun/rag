#!/usr/bin/env python3
"""Simple login test for ragMyAdmin"""
import requests
import json

def test_login():
    """Test basic login functionality"""
    session = requests.Session()
    
    print("=== Testing ragMyAdmin Login ===")
    
    # Test unauthenticated access
    resp = session.get("http://localhost:8792/ragmyadmin/", allow_redirects=False)
    print(f"1. Unauthenticated access: {resp.status_code} (should be 302)")
    
    # Get login page
    resp = session.get("http://localhost:8792/ragmyadmin/login")
    print(f"2. Login page access: {resp.status_code} (should be 200)")
    
    # Try login without CSRF (should work as CSRF is disabled for testing)
    login_data = {
        'username': 'goodsun',
        'password': 'TestPassword123'
    }
    
    resp = session.post("http://localhost:8792/ragmyadmin/login", data=login_data, allow_redirects=False)
    print(f"3. Login attempt: {resp.status_code} (should be 302)")
    if resp.status_code == 302:
        location = resp.headers.get('Location', '')
        print(f"   Redirect location: {location}")
    
    # Test dashboard access after login
    resp = session.get("http://localhost:8792/ragmyadmin/")
    print(f"4. Dashboard after login: {resp.status_code} (should be 200)")
    
    # Test API access
    resp = session.get("http://localhost:8792/ragmyadmin/api/collections")
    print(f"5. Collections API: {resp.status_code} (should be 200)")
    if resp.status_code == 200:
        try:
            collections = resp.json()
            print(f"   Found {len(collections)} collections")
        except:
            print(f"   Response text: {resp.text[:100]}...")
    
    # Test Phase 1 restriction (viewer user)
    print("\n--- Testing Phase 1 Policy ---")
    viewer_session = requests.Session()
    
    # Login as viewer
    resp = viewer_session.post("http://localhost:8792/ragmyadmin/login", data={
        'username': 'testviewer',
        'password': 'TestViewer123'
    }, allow_redirects=True)
    
    print(f"6. Viewer login: {resp.status_code} (should be 200)")
    
    # Test POST request (should be blocked for viewer)
    test_data = {"collection": "test", "query": "test"}
    resp = viewer_session.post("http://localhost:8792/ragmyadmin/api/search", json=test_data)
    print(f"7. Viewer search API: {resp.status_code} (should work - read operation)")
    
    # Test modification API (should be blocked)
    update_data = {"collection": "test", "id": "test", "document": "test"}
    resp = viewer_session.post("http://localhost:8792/ragmyadmin/api/update_chunk", json=update_data)
    print(f"8. Viewer update API: {resp.status_code} (should be 403 - blocked)")

if __name__ == "__main__":
    test_login()
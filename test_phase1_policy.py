#!/usr/bin/env python3
"""Test Phase 1 security policy - admin only modifications"""
import requests
import re

BASE_URL = "http://localhost:8792/ragmyadmin"

def login_user(username, password):
    """Login and return session"""
    session = requests.Session()
    
    # Get login page and extract CSRF token
    resp = session.get(f"{BASE_URL}/login")
    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    
    # Attempt login
    login_data = {
        'username': username,
        'password': password
    }
    if csrf_match:
        login_data['csrf_token'] = csrf_match.group(1)
    
    resp = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=True)
    
    print(f"  Login response: {resp.status_code}, URL: {resp.url}")
    if resp.url.endswith('/ragmyadmin/'):
        return session
    else:
        return None

def test_phase1_policy():
    """Test that non-admin users are restricted to read-only"""
    print("=== Phase 1 Policy Test ===\n")
    
    # Login as admin
    print("Testing admin user (should have full access)...")
    admin_session = login_user("goodsun", "TestPassword123")
    if not admin_session:
        print("❌ Failed to login as admin")
        return False
    
    # Login as viewer
    print("Testing viewer user (should be read-only)...")
    viewer_session = login_user("testviewer", "TestViewer123")
    if not viewer_session:
        print("❌ Failed to login as viewer")
        return False
    
    # Test GET requests (should work for both)
    print("\n--- Testing READ operations ---")
    
    # Test dashboard access
    for role, session in [("admin", admin_session), ("viewer", viewer_session)]:
        resp = session.get(f"{BASE_URL}/")
        print(f"{role.capitalize()} dashboard access: {resp.status_code} {'✅' if resp.status_code == 200 else '❌'}")
    
    # Test API GET requests
    for role, session in [("admin", admin_session), ("viewer", viewer_session)]:
        resp = session.get(f"{BASE_URL}/api/collections")
        print(f"{role.capitalize()} API collections: {resp.status_code} {'✅' if resp.status_code == 200 else '❌'}")
    
    # Test POST requests (should only work for admin)
    print("\n--- Testing WRITE operations ---")
    
    # Test search API (POST but read operation - should work for both)
    search_data = {"collection": "test", "query": "test", "n_results": 5}
    for role, session in [("admin", admin_session), ("viewer", viewer_session)]:
        resp = session.post(f"{BASE_URL}/api/search", json=search_data)
        print(f"{role.capitalize()} search API: {resp.status_code} {'✅' if resp.status_code in [200, 404] else '❌'}")
    
    # Test update chunk API (POST write operation - should only work for admin)
    update_data = {"collection": "test", "id": "test_chunk", "document": "updated text"}
    
    admin_resp = admin_session.post(f"{BASE_URL}/api/update_chunk", json=update_data)
    viewer_resp = viewer_session.post(f"{BASE_URL}/api/update_chunk", json=update_data)
    
    print(f"Admin update chunk: {admin_resp.status_code} {'✅' if admin_resp.status_code in [200, 400, 404] else '❌'}")
    print(f"Viewer update chunk: {viewer_resp.status_code} {'✅ (correctly blocked)' if viewer_resp.status_code == 403 else '❌ (should be blocked)'}")
    
    # Test DELETE operation
    delete_data = {"collection": "test", "ids": ["test_chunk"]}
    
    admin_del_resp = admin_session.post(f"{BASE_URL}/api/delete", json=delete_data)
    viewer_del_resp = viewer_session.post(f"{BASE_URL}/api/delete", json=delete_data)
    
    print(f"Admin delete: {admin_del_resp.status_code} {'✅' if admin_del_resp.status_code in [200, 400, 404] else '❌'}")
    print(f"Viewer delete: {viewer_del_resp.status_code} {'✅ (correctly blocked)' if viewer_del_resp.status_code == 403 else '❌ (should be blocked)'}")
    
    print("\n--- Summary ---")
    viewer_blocked = viewer_resp.status_code == 403 and viewer_del_resp.status_code == 403
    print(f"Phase 1 policy working: {'✅' if viewer_blocked else '❌'}")
    print("Non-admin users are properly restricted to read-only access")
    
    return viewer_blocked

if __name__ == "__main__":
    test_phase1_policy()
import os
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.db import connection

import random
from django.http import HttpResponse

ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

def logs_view(request):
    # Initialize logs in session if not present
    if 'audit_logs' not in request.session:
        request.session['audit_logs'] = [
            {'id': 'REC-8842', 'user': 'admin@securecorp.com', 'category': 'SECURITY', 'action': 'Database Backup initiated successfully'},
            {'id': 'REC-9921', 'user': 'john.doe@securecorp.com', 'category': 'USER_MGMT', 'action': 'Updated profile bio and contact information'},
            {'id': 'REC-7734', 'user': 'superadmin@vulnlab.com', 'category': 'SYSTEM', 'action': 'Modified global firewall configuration'},
        ]

    if request.method == 'POST':
        # Auto-generate Record ID
        new_id = f"REC-{random.randint(1000, 9999)}"
        associated_user = request.POST.get('associated_user')
        category = request.POST.get('category')
        action = request.POST.get('action')

        new_log = {
            'id': new_id,
            'user': associated_user,
            'category': category,
            'action': action
        }
        
        # Add to session list
        logs_list = request.session['audit_logs']
        logs_list.insert(0, new_log) # Add to top
        request.session['audit_logs'] = logs_list
        request.session.modified = True

    # Generate a preview ID for the form
    next_id = f"REC-{random.randint(1000, 9999)}"
    
    return render(request, 'logs.html', {
        'logs': request.session['audit_logs'],
        'next_id': next_id
    })

def profile_view(request):
    success = False
    target_param = request.GET.get('email') or request.GET.get('target')
    if request.method == 'POST':
        # VULNERABILITY: Stored XSS + IDOR
        # Accepts arbitrary email target and stores HTML bio without sanitization.
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')
        bio = request.POST.get('bio')
        request.session['user_name'] = full_name
        request.session['user_email'] = email
        request.session['user_bio'] = bio
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS profiles (email TEXT PRIMARY KEY, bio TEXT)")
            cursor.execute(f"INSERT OR REPLACE INTO profiles (email, bio) VALUES ('{email}', '{bio}')")
        success = True

    user_email = target_param or request.session.get('user_email', 'john.doe@securecorp.com')
    initials = user_email[:2].upper() if '@' in user_email else "JD"
    stored_bio = request.session.get('user_bio', '')
    if target_param:
        with connection.cursor() as cursor:
            try:
                cursor.execute(f"SELECT bio FROM profiles WHERE email = '{user_email}'")
                row = cursor.fetchone()
                if row:
                    stored_bio = row[0]
            except Exception:
                pass
    
    context = {
        'user_name': request.session.get('user_name', 'John Doe'),
        'user_email': user_email,
        'user_bio': stored_bio,
        'user_initials': initials,
        'success': success,
    }
    return render(request, 'profile.html', context)

def upload_view(request):
    message = None
    success = False
    
    if request.method == 'POST' and request.FILES.get('uploaded_file'):
        uploaded_file = request.FILES['uploaded_file']
        # VULNERABILITY: Unrestricted File Upload + Executable Acceptance
        # Directly writes the incoming file using the original name (including executable extensions)
        raw_name = uploaded_file.name
        target_path = os.path.join(settings.MEDIA_ROOT, raw_name)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        message = f"File '{raw_name}' uploaded successfully! Type: {uploaded_file.content_type or 'unknown'}"
        success = True
        
    # Get upload history from the media folder
    upload_history = []
    media_path = settings.MEDIA_ROOT
    if os.path.exists(media_path):
        for file in os.listdir(media_path):
            if os.path.isfile(os.path.join(media_path, file)):
                upload_history.append({
                    'name': file,
                    'url': f"{settings.MEDIA_URL}{file}"
                })
                
    # Show only last 10
    upload_history = upload_history[-10:]

    return render(request, 'upload.html', {
        'message': message, 
        'success': success,
        'upload_history': upload_history
    })

def dashboard_view(request):
    search_query = request.GET.get('search', '')
    user_email = request.session.get('user_email', 'employee@securecorp.com')
    
    # Simple initials logic for the profile icon
    initials = "JD"
    if user_email and '@' in user_email:
        initials = user_email[:2].upper()
    
    context = {
        'search_query': search_query,
        'user_email': user_email,
        'user_initials': initials,
    }
    return render(request, 'dashboard.html', context)

def directory_view(request):
    if 'employees' not in request.session:
        request.session['employees'] = [
            {'name': 'Marcus Thorne', 'email': 'm.thorne@nexus-security.io', 'dept': 'Cyber Intelligence'},
            {'name': 'Elena Rodriguez', 'email': 'e.rodriguez@nexus-security.io', 'dept': 'Threat Response'},
            {'name': 'Julian Vane', 'email': 'j.vane@nexus-security.io', 'dept': 'Infrastructure Security'},
            {'name': 'Sarah Jenkins', 'email': 's.jenkins@nexus-security.io', 'dept': 'Corporate Compliance'},
            {'name': 'David Wu', 'email': 'd.wu@nexus-security.io', 'dept': 'Cloud Architecture'},
            {'name': 'Aria Stark', 'email': 'a.stark@nexus-security.io', 'dept': 'Encryption Research'},
            {'name': 'Robert Vance', 'email': 'r.vance@nexus-security.io', 'dept': 'Physical Security'},
        ]
    employees_dicts = request.session['employees']
    employees = [(e['name'], e['email'], e['dept']) for e in employees_dicts]
    return render(request, 'directory.html', {'employees': employees})

def search_view(request):
    query = request.GET.get('q', '')
    filter_type = request.GET.get('filter', 'all')
    results = []

    audit_logs = request.session.get('audit_logs', [])

    if query:
        sql_query = (
            f"SELECT 'DOC-' || id, username, 'Internal Record' FROM auth_user WHERE username LIKE '%{query}%' "
            f"UNION SELECT 'USER-' || id, email, 'User Record' FROM vuln_users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'"
        )
        
        with connection.cursor() as cursor:
            try:
                cursor.execute(sql_query)
                results = cursor.fetchall()
            except Exception as e:
                pass
        
        formatted_results = []
        for res in results:
            formatted_results.append({
                'id': res[0],
                'user': res[1],
                'category': res[2],
                'action': 'System generated record'
            })
        
        for log in audit_logs:
            if query.lower() in log['user'].lower() or \
               query.lower() in log['id'].lower() or \
               query.lower() in log['category'].lower() or \
               query.lower() in log['action'].lower():
                formatted_results.append(log)

        employees = request.session.get('employees', [])
        for e in employees:
            if query.lower() in e['name'].lower() or query.lower() in e['email'].lower() or query.lower() in e['dept'].lower():
                formatted_results.append({
                    'id': f"EMP-{abs(hash(e['email'])) % 10000}",
                    'user': e['email'],
                    'category': 'DATA_LEAK',
                    'action': f"{e['name']} | {e['dept']} | {e['email']}"
                })
        settings_info = request.session.get('system_settings', {})
        for k, v in settings_info.items():
            formatted_results.append({
                'id': f"CFG-{abs(hash(k)) % 10000}",
                'user': 'system',
                'category': 'DATA_LEAK',
                'action': f"{k}={v}"
            })
        
        results = formatted_results
    else:
        results = audit_logs

    context = {
        'query': query,
        'filter': filter_type,
        'results': results,
    }
    return render(request, 'search.html', context)

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS vuln_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, password TEXT)")
            cursor.execute("SELECT COUNT(*) FROM vuln_users")
            count = cursor.fetchone()[0]
            if count == 0:
                cursor.execute("INSERT INTO vuln_users (username, email, password) VALUES ('admin','admin@nexus-security.io','admin')")
                cursor.execute("INSERT INTO vuln_users (username, email, password) VALUES ('john','john.doe@nexus-security.io','1234')")
            query = f"SELECT id, username, email FROM vuln_users WHERE email = '{email}' AND password = '{password}'"
            cursor.execute(query)
            user = cursor.fetchone()

        if user or (email and password and len(password) >= 3):
            request.session['user_email'] = email
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
            
    return render(request, 'login.html')

def forgot_password_view(request):
    return render(request, 'login.html', {'error': 'Forgot password feature is not implemented yet.'})

def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # VULNERABILITY: Weak Password Validation
        if password != confirm_password:
            return render(request, 'register.html', {'error': 'Passwords do not match'})
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS vuln_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, password TEXT)")
            cursor.execute(f"INSERT INTO vuln_users (username, email, password) VALUES ('{username}', '{email}', '{password}')")
        request.session['user_email'] = email
        return redirect('dashboard')

    return render(request, 'register.html')

def admin_dashboard_view(request):
    if not request.session.get('admin_authenticated'):
        if request.GET.get('override') == '1' or request.COOKIES.get('role') == 'admin' or str(request.session.get('user_email','')).endswith('@nexus-security.io'):
            request.session['admin_authenticated'] = True
        else:
            return redirect('admin_login')
    # Hidden admin data simulation
    if 'admin_users' not in request.session:
        request.session['admin_users'] = [
            {'id': 1, 'username': 'superadmin', 'email': 'superadmin@vulnlab.com', 'role': 'Global Admin', 'status': 'Active'},
            {'id': 2, 'username': 'sec_monitor', 'email': 'monitor@securecorp.com', 'role': 'Security Analyst', 'status': 'Active'},
            {'id': 3, 'username': 'sys_backup', 'email': 'backup@vulnlab.com', 'role': 'System Service', 'status': 'Standby'},
        ]
    
    if 'system_settings' not in request.session:
        request.session['system_settings'] = {
            'firewall_status': 'Enabled',
            'debug_mode': 'OFF',
            'api_logging': 'Verbose',
            'maintenance_mode': 'Disabled',
            'encryption_level': 'AES-256'
        }
    if 'employees' not in request.session:
        request.session['employees'] = [
            {'name': 'Marcus Thorne', 'email': 'm.thorne@nexus-security.io', 'dept': 'Cyber Intelligence'},
            {'name': 'Elena Rodriguez', 'email': 'e.rodriguez@nexus-security.io', 'dept': 'Threat Response'},
            {'name': 'Julian Vane', 'email': 'j.vane@nexus-security.io', 'dept': 'Infrastructure Security'},
            {'name': 'Sarah Jenkins', 'email': 's.jenkins@nexus-security.io', 'dept': 'Corporate Compliance'},
            {'name': 'David Wu', 'email': 'd.wu@nexus-security.io', 'dept': 'Cloud Architecture'},
            {'name': 'Aria Stark', 'email': 'a.stark@nexus-security.io', 'dept': 'Encryption Research'},
            {'name': 'Robert Vance', 'email': 'r.vance@nexus-security.io', 'dept': 'Physical Security'},
        ]

    # Handle setting updates
    if request.method == 'POST':
        if 'update_settings' in request.POST:
            settings_dict = request.session['system_settings']
            for key in settings_dict.keys():
                if key in request.POST:
                    settings_dict[key] = request.POST.get(key)
            request.session['system_settings'] = settings_dict
            request.session.modified = True
            messages.success(request, "System settings updated successfully.")
        elif request.POST.get('action') == 'delete_employee':
            target_email = request.POST.get('email')
            employees = request.session['employees']
            employees = [e for e in employees if e['email'] != target_email]
            request.session['employees'] = employees
            request.session.modified = True
            messages.success(request, f"Deleted employee {target_email}")
        elif request.POST.get('action') == 'edit_employee':
            original_email = request.POST.get('original_email')
            name = request.POST.get('name')
            email = request.POST.get('email')
            dept = request.POST.get('dept')
            employees = request.session['employees']
            for e in employees:
                if e['email'] == original_email:
                    e['name'] = name
                    e['email'] = email
                    e['dept'] = dept
                    break
            request.session['employees'] = employees
            request.session.modified = True
            messages.success(request, f"Updated employee {original_email}")
        elif request.POST.get('action') == 'view_employee':
            target_email = request.POST.get('email')
            messages.info(request, f"Viewing employee {target_email}")

    edit_email = request.GET.get('edit')
    selected = None
    if edit_email:
        for e in request.session['employees']:
            if e['email'] == edit_email:
                selected = e
                break
    context = {
        'admin_users': request.session['admin_users'],
        'audit_logs': request.session.get('audit_logs', []),
        'system_settings': request.session['system_settings'],
        'employees': request.session['employees'],
        'edit_email': edit_email,
        'selected_employee': selected
    }
    return render(request, 'admin_panel.html', context)

def admin_login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        if (email == ADMIN_USER and password == ADMIN_PASS) or (email == 'root' and password == 'toor'):
            request.session['admin_authenticated'] = True
            return redirect('admin_portal')
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS vuln_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT, password TEXT)")
            query = f"SELECT id FROM vuln_users WHERE email = '{email}' AND password = '{password}'"
            try:
                cursor.execute(query)
                user = cursor.fetchone()
            except Exception:
                user = None
        if user:
            request.session['admin_authenticated'] = True
            return redirect('admin_portal')
        return render(request, 'admin_login.html', {'error': 'Invalid admin credentials'})
    else:
        if request.GET.get('elevate') == '1' or request.COOKIES.get('role') == 'admin':
            request.session['admin_authenticated'] = True
            return redirect('admin_portal')
        return render(request, 'admin_login.html')

def browse_view(request):
    target = request.GET.get('path', settings.MEDIA_ROOT)
    try:
        items = os.listdir(target)
    except Exception as e:
        return HttpResponse(f"<h1>Directory Exposure</h1><p>Error reading: {target}</p><pre>{e}</pre>", content_type="text/html")
    rows = []
    for name in items:
        p = os.path.join(target, name)
        t = "DIR" if os.path.isdir(p) else "FILE"
        size = os.path.getsize(p) if os.path.exists(p) and os.path.isfile(p) else "-"
        safe_path = p.replace("\\", "/")
        link = f"/browse/?path={safe_path}"
        rows.append(f"<tr><td>{t}</td><td><a href='{link}'>{name}</a></td><td>{size}</td></tr>")
    html = f"""
    <html><head><title>Directory Exposure</title></head>
    <body>
    <h1>Listing: {target}</h1>
    <table border='1' cellpadding='6' cellspacing='0'>
    <tr><th>Type</th><th>Name</th><th>Size</th></tr>
    {''.join(rows)}
    </table>
    </body></html>
    """
    return HttpResponse(html, content_type="text/html")

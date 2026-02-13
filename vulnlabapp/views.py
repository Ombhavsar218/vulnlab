import os
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.db import connection

import random

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
    if request.method == 'POST':
        # VULNERABILITY: Stored XSS
        # We store the bio directly in the session (simulating a database)
        # and render it with |safe in the template.
        request.session['user_name'] = request.POST.get('full_name')
        request.session['user_email'] = request.POST.get('email')
        request.session['user_bio'] = request.POST.get('bio')
        success = True

    user_email = request.session.get('user_email', 'john.doe@securecorp.com')
    initials = user_email[:2].upper() if '@' in user_email else "JD"
    
    context = {
        'user_name': request.session.get('user_name', 'John Doe'),
        'user_email': user_email,
        'user_bio': request.session.get('user_bio', ''),
        'user_initials': initials,
        'success': success,
    }
    return render(request, 'profile.html', context)

def upload_view(request):
    message = None
    success = False
    
    if request.method == 'POST' and request.FILES.get('uploaded_file'):
        uploaded_file = request.FILES['uploaded_file']
        
        # VULNERABILITY: Unrestricted File Upload
        # No validation of file extension or content type
        fs = FileSystemStorage()
        filename = fs.save(uploaded_file.name, uploaded_file)
        
        message = f"File '{filename}' uploaded successfully!"
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
    # Simple employee list without the search focus
    with connection.cursor() as cursor:
        cursor.execute("SELECT username, email, 'Department' FROM auth_user LIMIT 10")
        employees = cursor.fetchall()
    
    return render(request, 'directory.html', {'employees': employees})

def search_view(request):
    query = request.GET.get('q', '')
    filter_type = request.GET.get('filter', 'all')
    results = []

    # Get logs from session for searching
    audit_logs = request.session.get('audit_logs', [])

    if query:
        # VULNERABILITY: SQL Injection (Unsafe string concatenation)
        # Still performs database search for "Internal Records"
        sql_query = f"SELECT 'DOC-' || id, username, 'Internal Record' FROM auth_user WHERE username LIKE '%{query}%'"
        
        with connection.cursor() as cursor:
            try:
                cursor.execute(sql_query)
                results = cursor.fetchall()
            except Exception as e:
                pass
        
        # Convert DB results to a common format
        formatted_results = []
        for res in results:
            formatted_results.append({
                'id': res[0],
                'user': res[1],
                'category': res[2],
                'action': 'System generated record'
            })
        
        # Search through manually created Audit Logs in session
        for log in audit_logs:
            if query.lower() in log['user'].lower() or \
               query.lower() in log['id'].lower() or \
               query.lower() in log['category'].lower() or \
               query.lower() in log['action'].lower():
                formatted_results.append(log)
        
        results = formatted_results
    else:
        # When no query is provided, show all audit logs created by the user
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
        
        # Hardcoded credentials
        if email == 'superadmin@vulnlab.com' and password == 'P@ssw0rd123!':
            request.session['user_email'] = email
            return redirect('dashboard')

        # SQL Injection Vulnerability
        query = "SELECT * FROM auth_user WHERE email = '%s' AND password = '%s'" % (email, password)
        
        with connection.cursor() as cursor:
            cursor.execute(query)
            user = cursor.fetchone()

        if user:
            # For demonstration, we'll store the email in session
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
        
        return render(request, 'register.html', {'success': f'User {username} registered successfully with a weak password policy!'})

    return render(request, 'register.html')

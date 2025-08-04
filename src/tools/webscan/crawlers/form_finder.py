#!/usr/bin/env python3

from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from termcolor import colored

def find_forms(scanner):
    """
    Find forms in the discovered URLs.
    
    Args:
        scanner: The WebScanner instance
        
    Returns:
        list: Forms found on the discovered URLs
    """
    def process_url(url):
        """Process a URL to find forms"""
        try:
            response = scanner.session.get(url, timeout=scanner.timeout, verify=False)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return []
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms_found = []
            
            for form in soup.find_all('form'):
                form_info = {
                    'url': url,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': [],
                    'raw_html': str(form)  # Store raw HTML for detailed analysis
                }
                
                # Get full action URL
                if form_info['action'].startswith('/'):
                    form_info['action'] = scanner.base_url + form_info['action']
                elif not form_info['action'].startswith('http'):
                    form_info['action'] = urljoin(url, form_info['action'])
                
                # If no action is specified, default to the current URL
                if not form_info['action']:
                    form_info['action'] = url
                
                # Extract input fields
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_field.get('type', '')
                    input_name = input_field.get('name', '')
                    input_id = input_field.get('id', '')
                    input_value = input_field.get('value', '')
                    input_placeholder = input_field.get('placeholder', '')
                    input_required = input_field.has_attr('required')
                    
                    if input_name or input_id:
                        input_info = {
                            'name': input_name,
                            'id': input_id,
                            'type': input_type,
                            'value': input_value,
                            'placeholder': input_placeholder,
                            'required': input_required,
                            'tag': input_field.name  # input, textarea, or select
                        }
                        
                        # For select fields, extract options
                        if input_field.name == 'select':
                            input_info['options'] = []
                            for option in input_field.find_all('option'):
                                option_value = option.get('value', '')
                                option_text = option.get_text(strip=True)
                                input_info['options'].append({
                                    'value': option_value,
                                    'text': option_text
                                })
                        
                        # Skip hidden fields that don't seem important
                        if input_type == 'hidden' and input_name not in ['csrf_token', '_token', 'authenticity_token']:
                            continue
                        
                        # Skip submit, button, and image types as they are not parameters
                        if input_type not in ['submit', 'button', 'image', 'reset']:
                            form_info['inputs'].append(input_info)
                
                # Only include forms with at least one input field
                if form_info['inputs']:
                    # Categorize form based on inputs and action
                    form_info['category'] = categorize_form(form_info)
                    forms_found.append(form_info)
            
            return forms_found
        except Exception as e:
            if scanner.verbose:
                scanner.logger.error(f"Error processing URL {url} for forms: {str(e)}")
            return []
            
    def categorize_form(form_info):
        """Categorize the form based on its inputs and action"""
        # Default category
        category = "unknown"
        
        # Check form action for clues
        action_lower = form_info['action'].lower()
        
        # Login form
        if any(term in action_lower for term in ['login', 'signin', 'authenticate']):
            return "login"
        
        # Registration form
        if any(term in action_lower for term in ['register', 'signup', 'create-account']):
            return "registration"
        
        # Contact/feedback form
        if any(term in action_lower for term in ['contact', 'feedback', 'message']):
            return "contact"
        
        # Search form
        if any(term in action_lower for term in ['search', 'find', 'query']):
            return "search"
        
        # Check input types and names for clues
        input_names = [input_info.get('name', '').lower() for input_info in form_info['inputs']]
        input_types = [input_info.get('type', '').lower() for input_info in form_info['inputs']]
        
        # Login form
        if ('password' in input_types) and any(term in ' '.join(input_names) for term in ['user', 'email', 'login']):
            return "login"
        
        # Registration form
        if ('password' in input_types) and any(term in ' '.join(input_names) for term in ['confirm', 'register', 'signup']):
            return "registration"
        
        # Contact/feedback form
        if ('textarea' in [input_info.get('tag', '') for input_info in form_info['inputs']]) and any(term in ' '.join(input_names) for term in ['name', 'email', 'subject', 'message']):
            return "contact"
        
        # Search form
        if any(term in ' '.join(input_names) for term in ['search', 'query', 'q', 'find']):
            return "search"
        
        # File upload form
        if 'file' in input_types:
            return "file_upload"
        
        # Newsletter/subscription form
        if len(input_names) <= 2 and ('email' in ' '.join(input_names)) and form_info['method'] == 'POST':
            return "newsletter"
        
        # Payment form
        if any(term in ' '.join(input_names) for term in ['card', 'credit', 'payment', 'cvv', 'ccv']):
            return "payment"
        
        return category
    
    # Use ThreadPoolExecutor to process URLs in parallel
    all_forms = []
    with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
        # Use list to force execution of the generator
        for forms in executor.map(process_url, scanner.discovered_urls):
            all_forms.extend(forms)
    
    # Update the scanner's forms
    scanner.forms = all_forms
    
    # Categorize forms for better understanding
    form_categories = {}
    for form in all_forms:
        category = form.get('category', 'unknown')
        if category not in form_categories:
            form_categories[category] = 0
        form_categories[category] += 1
    
    # Provide a summary of the forms found
    if scanner.verbose:
        scanner.logger.info(f"Found {len(all_forms)} forms:")
        for category, count in form_categories.items():
            scanner.logger.info(f"  {category.replace('_', ' ').title()}: {count}")
    
    # Note potentially interesting forms for security testing
    if scanner.verbose:
        for form in all_forms:
            category = form.get('category', 'unknown')
            if category in ['login', 'registration', 'file_upload', 'payment']:
                scanner.logger.info(f"  Interesting form found: {category} at {form['url']}")
    
    return all_forms 
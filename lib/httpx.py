#!/usr/bin/env python3
"""
Headless Browser HTTP Response Capture Script
Captures full HTTP request/response using headless browser for all domains in data/*.all files
"""

import os
import sys
import glob
import json
from pathlib import Path
from urllib.parse import urlparse

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[!] Playwright not installed!")
    print("[*] Install with: pip3 install playwright && playwright install chromium")
    sys.exit(1)


DATA_DIR = "/root/reconftw/data"
OUTPUT_DIR = "/opt/response"


def save_http_response(domain, url, request_data, response_data, response_body):
    """Save HTTP request/response to file"""
    
    # Create domain-specific directory
    parsed = urlparse(url)
    subdomain = parsed.netloc or domain
    output_path = Path(OUTPUT_DIR) / domain
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create output file: /tmp/response/{domain}/{subdomain}
    output_file = output_path / subdomain
    
    with open(output_file, 'w', encoding='utf-8') as f:
        # Write response status and headers
        f.write(f"HTTP/1.1 {response_data['status']} {response_data['statusText']}\n")
        for key, value in response_data.get('headers', {}).items():
            f.write(f"{key}: {value}\n")
        f.write("\n")
        
        # Write response body
        if response_body:
            f.write(response_body)
        f.write("\n\n")
        f.write(url)
    
    return output_file


def capture_with_browser(url, domain, timeout=6000):
    """Capture HTTP traffic using headless browser"""
    
    # Check if response already exists
    from urllib.parse import urlparse
    parsed = urlparse(url)
    subdomain = parsed.netloc or domain
    output_file = Path(OUTPUT_DIR) / domain / subdomain
    
    if output_file.exists():
        print(f"  [⏭] Already exists, skipping: {output_file}")
        return True
    
    requests = []
    responses = {}
    
    with sync_playwright() as p:
        try:
            # Launch headless browser
            browser = p.chromium.launch(
                headless=True,
                args=['--ignore-certificate-errors', '--ignore-certificate-errors-spki-list']
            )
            context = browser.new_context(
                user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                ignore_https_errors=True,
                accept_downloads=False
            )
            page = context.new_page()
            # Set default timeout for all operations
            page.set_default_timeout(timeout)
            
            # Capture network traffic
            def handle_request(request):
                try:
                    post_data = request.post_data
                except:
                    post_data = None  # Binary or non-UTF-8 data
                
                requests.append({
                    'url': request.url,
                    'method': request.method,
                    'headers': request.headers,
                    'post_data': post_data
                })
            
            def handle_response(response):
                responses[response.url] = {
                    'status': response.status,
                    'statusText': response.status_text,
                    'headers': response.headers,
                    'url': response.url
                }
            
            # Visit the URL and capture initial response only (no redirect following)
            print(f"  [*] Visiting: {url}")
            
            # Track first response
            first_response_data = {'captured': False, 'status': None, 'headers': None, 'body': None}
            
            def capture_response(response):
                # Capture the FIRST response from our requested URL
                # Normalize URLs by removing trailing slashes for comparison
                request_url_normalized = response.request.url.rstrip('/')
                url_normalized = url.rstrip('/')
                
                if not first_response_data['captured'] and request_url_normalized == url_normalized:
                    first_response_data['captured'] = True
                    first_response_data['status'] = response.status
                    first_response_data['headers'] = response.headers
                    try:
                        first_response_data['body'] = response.text()
                    except:
                        first_response_data['body'] = ""
            
            page.on('response', capture_response)
            
            # Make the request but block redirect navigation
            all_responses_received = []
            
            def log_all(response):
                all_responses_received.append(response.url)
            page.on('response', log_all)
            
            try:
                # Use domcontentloaded which is faster and won't wait for redirects
                page.goto(url, timeout=timeout, wait_until='domcontentloaded')
            except Exception as e:
                # Allow some common errors when blocking redirects
                pass
            
            # Check if we got a response
            if first_response_data['captured']:
                request_data = {
                    'url': url,
                    'method': 'GET',
                    'headers': {}
                }
                
                response_data = {
                    'status': first_response_data['status'],
                    'statusText': '',  # Will be filled from status
                    'headers': first_response_data['headers'],
                    'url': url
                }
                
                # Add status text based on status code
                status_texts = {
                    200: 'OK', 201: 'Created', 204: 'No Content',
                    301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 
                    304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
                    400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
                    500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable'
                }
                response_data['statusText'] = status_texts.get(first_response_data['status'], 'Unknown')
                
                output_file = save_http_response(domain, url, request_data, response_data, first_response_data['body'])
                print(f"  [✓] Saved to: {output_file}")
                
                return True
            
            return False
            
        except Exception as e:
            error_msg = str(e).split('\n')[0]  # Get first line of error
            print(f"  [✗] Error visiting {url}: {error_msg}")
            
            # Try to save whatever response we got before the error
            if responses:
                try:
                    # Get the first response (usually the main page)
                    main_url = list(responses.keys())[0] if responses else url
                    response_data = responses.get(main_url, {
                        'status': 0,
                        'statusText': 'Error',
                        'headers': {},
                        'url': url
                    })
                    
                    request_data = {
                        'url': url,
                        'method': 'GET',
                        'headers': {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
                    }
                    
                    # Try to get page content
                    try:
                        body = page.content()
                    except:
                        body = f"[Error: {error_msg}]"
                    
                    output_file = save_http_response(domain, url, request_data, response_data, body)
                    print(f"  [~] Partial response saved to: {output_file}")
                    return True
                except Exception as save_error:
                    print(f"  [!] Could not save partial response: {save_error}")
            
            return False
        
        finally:
            try:
                browser.close()
            except:
                pass
    
    return False


def process_domain_file(file_path):
    """Process a single .all file"""
    
    filename = os.path.basename(file_path)
    domain = filename.replace('.txt.all', '')
    
    print(f"\n[*] Processing: {filename}")
    print(f"[*] Domain: {domain}")
    
    # Read domains from file
    with open(file_path, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Found {len(domains)} domains to process")
    
    success_count = 0
    for i, subdomain in enumerate(domains, 1):
        # Try HTTPS first, then HTTP
        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}"
            print(f"[{i}/{len(domains)}] {url}")
            
            if capture_with_browser(url, domain):
                success_count += 1
                break  # Success, move to next domain
    
    print(f"[✓] Completed {domain}: {success_count}/{len(domains)} successful")
    return success_count


def main():
    """Main function"""
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Find all .all files
    pattern = os.path.join(DATA_DIR, "*.all")
    all_files = glob.glob(pattern)
    
    if not all_files:
        print(f"[!] No .all files found in {DATA_DIR}")
        sys.exit(1)
    
    print(f"[*] Found {len(all_files)} .all files to process")
    print(f"[*] Output directory: {OUTPUT_DIR}")
    print("=" * 60)
    
    total_success = 0
    for file_path in all_files:
        success = process_domain_file(file_path)
        total_success += success
    
    print("\n" + "=" * 60)
    print(f"[✓] All files processed successfully!")
    print(f"[*] Total captures: {total_success}")
    print(f"[*] Results saved in: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()

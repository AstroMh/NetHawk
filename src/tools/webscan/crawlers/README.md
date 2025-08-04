# Web Crawlers Module

## Overview

The Web Crawlers module provides comprehensive web crawling and route extraction capabilities for the NetHawk web scanner. This module includes advanced techniques for discovering URLs, extracting routes from various sources, and analyzing website structure.

## Modules

### 1. Route Extractor (`route_extractor.py`)

**Advanced Route Extractor for comprehensive website route discovery**

The Route Extractor is a sophisticated module that implements comprehensive route extraction techniques including:

#### Core Features

- **Sitemap Extraction and Parsing**
  - XML sitemap parsing with namespace support
  - HTML sitemap extraction
  - Text sitemap parsing
  - Sitemap index handling
  - Sub-sitemap discovery

- **Robots.txt Analysis**
  - Sitemap directive extraction
  - Allow/Disallow path discovery
  - Robots.txt route extraction

- **JavaScript Route Discovery**
  - API endpoint extraction from JS files
  - Route pattern detection in JavaScript
  - Dynamic route discovery

- **API Endpoint Discovery**
  - Common API pattern detection
  - REST API endpoint discovery
  - GraphQL endpoint detection
  - Service endpoint identification

- **Dynamic Route Detection**
  - Parameter-based route detection
  - Hash-based route identification
  - Query string route analysis

- **Route Categorization and Analysis**
  - Static route identification
  - Dynamic route classification
  - API route categorization
  - Route pattern analysis

#### Sitemap Locations Supported

```
/sitemap.xml
/sitemap_index.xml
/sitemap/sitemap.xml
/sitemap/sitemap_index.xml
/sitemap1.xml
/sitemap2.xml
/sitemap3.xml
/sitemap.txt
/sitemap.html
/sitemap/sitemap.html
/sitemap/sitemap.txt
/robots.txt
```

#### Route Patterns Detected

**API Endpoints:**
- `/api/[endpoint]`
- `/v1/[endpoint]`, `/v2/[endpoint]`, `/v3/[endpoint]`
- `/rest/[endpoint]`
- `/graphql`
- `/gql`
- `/service/[endpoint]`
- `/json/[endpoint]`

**Admin Panels:**
- `/admin`
- `/administrator`
- `/wp-admin`
- `/console`
- `/manage`
- `/panel`
- `/control`
- `/backend`

**Authentication Routes:**
- `/login`
- `/register`
- `/signup`
- `/signin`
- `/logout`
- `/auth`
- `/account`
- `/profile`

**Dynamic Routes:**
- Numeric IDs (`/123`)
- Hash-based routes (`/a1b2c3d4`)
- Query parameters (`/page?param=value`)
- Hash fragments (`/page#section`)

#### Usage

```python
from src.tools.webscan.crawlers.route_extractor import RouteExtractor

# Initialize route extractor with scanner instance
route_extractor = RouteExtractor(scanner_instance)

# Run comprehensive route extraction
routes = route_extractor.run()

# Access categorized routes
all_routes = routes['all_routes']
sitemap_routes = routes['sitemap_routes']
robots_routes = routes['robots_routes']
api_routes = routes['api_routes']
static_routes = routes['static_routes']
dynamic_routes = routes['dynamic_routes']
```

#### Output Categories

- **all_routes**: Complete set of discovered routes
- **sitemap_routes**: Routes extracted from sitemaps
- **robots_routes**: Routes found in robots.txt
- **crawled_routes**: Routes discovered through crawling
- **api_routes**: API endpoints and service routes
- **static_routes**: Static pages and resources
- **dynamic_routes**: Dynamic and parameterized routes

### 2. URL Crawler (`url_crawler.py`)

**Comprehensive URL discovery and crawling**

The URL Crawler provides advanced web crawling capabilities:

#### Features

- **Breadth-first crawling**
- **Domain restriction**
- **URL categorization**
- **Static resource detection**
- **Form discovery**
- **Authentication area detection**

#### URL Categories

- **Static Resources**: CSS, JS, images, fonts
- **API Endpoints**: REST, GraphQL, service endpoints
- **Forms**: Login, registration, contact forms
- **Authenticated Areas**: User accounts, profiles, dashboards
- **Admin Areas**: Administrative panels and controls

### 3. Directory Brute (`directory_brute.py`)

**Directory and file enumeration**

Advanced directory brute forcing with:

- **Custom wordlists**
- **Response analysis**
- **Status code filtering**
- **Content length analysis**
- **Response time analysis**

### 4. Form Finder (`form_finder.py`)

**Form discovery and analysis**

Comprehensive form detection including:

- **HTML form extraction**
- **JavaScript form detection**
- **Form field analysis**
- **Form action discovery**
- **Form method detection**

## Advanced Features

### Comprehensive Route Detection

The route extractor implements sophisticated detection techniques:

1. **XML Sitemap Parsing**
   - Namespace-aware XML parsing
   - Sitemap index handling
   - Sub-sitemap discovery
   - URL extraction with metadata

2. **HTML Sitemap Extraction**
   - Link extraction from HTML sitemaps
   - Relative URL resolution
   - Domain validation
   - Duplicate removal

3. **Text Sitemap Parsing**
   - Line-by-line URL extraction
   - Comment filtering
   - URL validation
   - Format detection

4. **Robots.txt Analysis**
   - Sitemap directive extraction
   - Allow/Disallow path discovery
   - User-agent specific rules
   - Crawl delay detection

5. **JavaScript Route Discovery**
   - API endpoint pattern matching
   - Dynamic route detection
   - AJAX endpoint discovery
   - Service endpoint identification

### Route Categorization

Routes are automatically categorized based on patterns:

- **Static Routes**: HTML pages, documentation, static content
- **Dynamic Routes**: Parameterized URLs, IDs, hashes
- **API Routes**: REST endpoints, GraphQL, services
- **Admin Routes**: Administrative interfaces
- **Auth Routes**: Authentication and authorization pages

### Performance Optimization

- **Threading support** for parallel processing
- **Connection pooling** for efficient requests
- **Timeout handling** for reliable operation
- **Error recovery** for robust operation
- **Rate limiting** to respect server resources

### Security Considerations

- **Domain restriction** to prevent external crawling
- **File extension filtering** to avoid static resources
- **Content type validation** for proper parsing
- **Error handling** for graceful failure
- **Resource management** to prevent overload

## Configuration

The crawlers can be configured through the main scanner instance:

```python
# Scanner configuration
scanner_instance.verbose = True
scanner_instance.timeout = 10
scanner_instance.max_threads = 5
scanner_instance.target_url = "https://example.com"
```

## Output and Reporting

### Verbose Output

When verbose mode is enabled, the crawlers provide detailed information:

```
[*] Starting comprehensive route extraction...
    Target: https://example.com
    Using 12 sitemap locations
    Advanced route detection enabled

  [+] Extracting sitemap routes...
  [+] Extracting robots.txt routes...
  [+] Extracting routes from crawled pages...
  [+] Extracting API routes...
  [+] Categorizing routes...

[+] Route extraction completed
    Total routes found: 150
    Sitemap routes: 45
    Robots.txt routes: 12
    Crawled routes: 93
    API routes: 8
    Static routes: 120
    Dynamic routes: 30

    Advanced features used:
      ✓ XML sitemap parsing
      ✓ HTML sitemap extraction
      ✓ Text sitemap parsing
      ✓ Robots.txt analysis
      ✓ JavaScript route extraction
      ✓ API endpoint discovery
      ✓ Route categorization
      ✓ Dynamic route detection
```

### Route Categories

The crawlers provide detailed categorization:

- **Sitemap Routes**: Routes discovered from sitemaps
- **Robots Routes**: Routes found in robots.txt
- **Crawled Routes**: Routes discovered through crawling
- **API Routes**: API endpoints and services
- **Static Routes**: Static pages and resources
- **Dynamic Routes**: Dynamic and parameterized routes

## Integration

The crawlers integrate seamlessly with the main web scanner:

```python
# In the main scanner
from src.tools.webscan.crawlers.route_extractor import RouteExtractor

# Initialize route extractor
route_extractor = RouteExtractor(self)

# Extract routes
routes = route_extractor.run()

# Use routes for further scanning
for route in routes['all_routes']:
    # Perform vulnerability scanning on each route
    self.scan_route(route)
```

## Best Practices

1. **Respect robots.txt**: Always check robots.txt before crawling
2. **Use appropriate timeouts**: Set reasonable timeouts for reliable operation
3. **Limit crawling depth**: Avoid infinite crawling loops
4. **Handle errors gracefully**: Implement proper error handling
5. **Validate URLs**: Always validate discovered URLs before processing
6. **Categorize routes**: Use route categorization for targeted scanning
7. **Monitor performance**: Track crawling performance and adjust settings
8. **Respect rate limits**: Implement rate limiting to avoid server overload

## Contributing

When adding new crawler features:

1. Follow the existing code structure
2. Add comprehensive error handling
3. Include verbose output options
4. Add proper documentation
5. Test thoroughly with various websites
6. Consider performance implications
7. Add appropriate logging
8. Include configuration options

## License

This module is part of the NetHawk project and follows the same licensing terms. 
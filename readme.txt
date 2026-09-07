=== YGB Chat Support ===
Contributors: ygb
Tags: chat, support, whatsapp, woocommerce, customer-service, live-chat
Requires at least: 7.0
Tested up to: 7.0.2
Stable tag: 3.0.2
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A secure, fully hardened chat widget for customer support with instant messaging integration and WooCommerce compatibility.

== Description ==

YGB Chat Support is a comprehensive chat solution that connects your customers directly with your support team. This plugin has been **security hardened** following WordPress best practices and is ready for production environments.

### ✨ Key Features

* 🔒 **Security Hardened**: Rate limiting, CSRF protection, input sanitization, output escaping, proxy/Cloudflare support
* 📱 **Responsive Design**: Works perfectly on desktop, tablet, and mobile devices
* 🛍️ **WooCommerce Integration**: Automatically shows product info on product pages
* 🎨 **Fully Customizable**: Button colors, tooltips, logos, positioning, and more
* 📧 **Email Notifications**: Optional email alerts when customers start a chat
* 🌍 **Internationalization Ready**: Fully translatable with Spanish included
* 🚀 **Lightweight**: Minimal impact on site performance (no external dependencies)
* 🛡️ **GDPR Friendly**: No personal data stored, messages go directly to your chat
* 🌐 **Proxy Support**: Works with Cloudflare, load balancers, and reverse proxies
* 👤 **Role Management**: Configurable user roles for message permissions

### 🛡️ Security Features (v3.0.2)

| Feature | Description |
|---------|-------------|
| **Rate Limiting** | Maximum 5 messages per 5 minutes per IP address |
| **Message Limits** | 1000 characters maximum per message |
| **Anti-Spam Filter** | Built-in blocked words list (customizable via filter) |
| **Phone Validation** | Validates international phone number format |
| **CSRF Protection** | Nonce verification on all AJAX requests |
| **XSS Prevention** | Complete output escaping throughout the plugin |
| **SQLi Prevention** | Prepared statements for all database queries |
| **Capability Checks** | Proper user permission verification for admin actions |
| **Proxy Support** | Detects real IP behind Cloudflare and proxies |
| **Image Validation** | MIME type and protocol validation for logos |
| **Role Control** | Filter `ygb_chat_allowed_roles` for granular access |
| **AJAX Termination** | Explicit `wp_die()` after all AJAX responses for safety |
| **Consistent Query Escaping** | Unified `%%` wildcard escaping in all database queries |

**🔄 What's New in v3.0.2:**
- Fixed missing `wp_die()` after AJAX success/error responses
- Corrected inconsistent LIKE wildcard escaping in uninstall.php
- Added filter `ygb_chat_allowed_logo_extensions` for developers
- Improved code consistency between main plugin and uninstaller
- Updated compatibility for WordPress 7.0.2+

### 🎯 Use Cases

* **E-commerce stores**: Let customers ask about products before purchasing
* **Service businesses**: Provide quick support for service inquiries
* **Restaurants**: Accept reservations and answer menu questions
* **Real estate**: Answer property inquiries instantly
* **Education**: Provide student support and course information

### 🔧 WooCommerce Integration

When activated on a WooCommerce site, the chat window automatically displays:
- Product name
- Product price
- Product link (included in the message)

### 📧 Email Notifications

Optional email notifications include:
- User name (if logged in)
- User email (if available)
- Full message content
- Page URL where chat was initiated
- Timestamp
- IP address (for spam prevention)
- User agent string (truncated to 512 chars)

### 🌍 Translation Ready

The plugin includes a complete .pot file and Spanish translation. Other translations can be contributed via WordPress.org.

### 🎨 Customization Options

**General Settings:**
- Chat number (international format)
- Notification email address
- Welcome message (supports user name variable)
- Tooltip text and colors
- Custom logo upload (with validation)

**Appearance:**
- Button color and hover color
- Chat window background color
- Logo size (30-100% of button)
- Icon size (30-120px desktop, 30-100px mobile)

**Positioning:**
- Left or right alignment
- Fine offset controls (0-200px for desktop, 0-100px for mobile)
- Separate settings for desktop and mobile devices

### 🔧 Developer Filters

```php
// Allow additional roles to send messages
add_filter('ygb_chat_allowed_roles', function($roles) {
    $roles[] = 'custom_role';
    return $roles;
});

// Add custom blocked words
add_filter('ygb_chat_blocked_words', function($words) {
    $words[] = 'your-blocked-word';
    return $words;
});

// Add custom image extensions for logo
add_filter('ygb_chat_allowed_logo_extensions', function($extensions) {
    $extensions[] = 'ico';
    return $extensions;
});

💻 Compatibility
WordPress: 7.0 or higher (tested up to 7.0.2)

PHP: 8.0 or higher

WooCommerce: 5.0 or higher (optional)

Caching Plugins: Compatible with all major caching plugins (W3 Total Cache, WP Super Cache, LiteSpeed Cache, etc.)

== Changelog ==
= 3.0.2 - 2026-07-26 =

Fixed: Added missing wp_die() after AJAX responses for proper execution termination

Fixed: Corrected inconsistent LIKE wildcard escaping in uninstall.php (% → %%)

Added: Filter ygb_chat_allowed_logo_extensions for developers

Improved: Documentation and code consistency across all files

Compatibility: Updated requirements to WordPress 7.0.2+ and PHP 8.0+

= 3.0.1 - 2026-04-03 =

Security: Fixed SQL injection vulnerability in LIKE query

Security: Added proxy/Cloudflare support for IP detection

Security: Added double email sanitization on retrieval

Security: Added batch limit (1000) to transient cleanup

Security: Added image MIME type validation for logos

Security: Added protocol validation (http/https only) for logos

Security: Added user agent length limit (512 chars)

Security: Added role-based access control filter

Security: Added is_email() validation before using user email

Improved: Removed redundant return statements after wp_send_json

Improved: Error messages for logo validation

Improved: Welcome message escaping

Improved: Transient cleanup performance

Translation: Added Spanish (es_ES) translation (100% complete)

= 3.0.0 - 2024-04-02 =

Security: Complete security hardening release

Feature: WooCommerce integration

Feature: Responsive design

Feature: Customizable colors, logo, position

Feature: Email notifications

Feature: Tooltip with custom text

Compatibility: WordPress 5.0-7.0.2, PHP 7.4-8.3, WooCommerce 5.0-8.0

= 2.0.0 - 2023-10-15 =

Basic chat functionality

WhatsApp integration

Basic customization options

= 1.0.0 - 2023-01-10 =

Initial public release

Core chat features

== Upgrade Notice ==

= 3.0.2 =
Security patch: Important fixes for AJAX termination and database query consistency. Now requires WordPress 7.0+ and PHP 8.0+. Tested with WordPress 7.0.2.

= 3.0.1 =
Security hardening release. Includes 10+ security improvements. All users should update immediately.

= 3.0.0 =
Major security release with rate limiting, CSRF protection, and input sanitization. Backward compatible with previous settings.
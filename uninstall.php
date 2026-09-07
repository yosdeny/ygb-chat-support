<?php
/**
 * Uninstall script for YGB Chat Support
 * 
 * Removes all plugin options and cleans up transients
 * 
 * @package YGB_Chat_Support
 * @since   3.0.0
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// List of all options to delete
$options = [
    'ygb_chat_phone',
    'ygb_chat_email',
    'ygb_chat_button_color',
    'ygb_chat_button_hover_color',
    'ygb_chat_logo',
    'ygb_chat_logo_size',
    'ygb_chat_position',
    'ygb_chat_welcome',
    'ygb_chat_icon_size',
    'ygb_chat_icon_size_mobile',
    'ygb_chat_bg_color',
    'ygb_chat_tooltip_text',
    'ygb_chat_tooltip_bg_color',
    'ygb_chat_tooltip_text_color',
    'ygb_chat_offset_x',
    'ygb_chat_offset_y',
    'ygb_chat_offset_x_mobile',
    'ygb_chat_offset_y_mobile'
];

// Delete all options
foreach ($options as $option) {
    delete_option($option);
}

// Clean up all transients
global $wpdb;
$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->options} 
        WHERE option_name LIKE %s",
        '_transient_ygb_chat_rate_%%' // ← CORREGIDO: doble %% para evitar conflictos con prepare
    )
);

// Clean up scheduled events
wp_clear_scheduled_hook('ygb_chat_cleanup_transients');

// Clear any cached data
wp_cache_flush();
use wx_db::{
    effective_limit, msg_sub_type_label, split_local_type, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT,
    MSG_TYPE_APP, MSG_TYPE_TEXT,
};

// ---- effective_limit boundary tests ----

#[test]
fn effective_limit_zero_returns_default() {
    assert_eq!(effective_limit(0), DEFAULT_QUERY_LIMIT);
    assert_eq!(effective_limit(0), 1_000);
}

#[test]
fn effective_limit_over_max_is_clamped() {
    assert_eq!(effective_limit(20_000), MAX_QUERY_LIMIT);
    assert_eq!(effective_limit(20_000), 20_000);
}

#[test]
fn effective_limit_exactly_max() {
    assert_eq!(effective_limit(MAX_QUERY_LIMIT), MAX_QUERY_LIMIT);
}

#[test]
fn effective_limit_one_below_max() {
    assert_eq!(effective_limit(MAX_QUERY_LIMIT - 1), MAX_QUERY_LIMIT - 1);
}

#[test]
fn effective_limit_one_above_max() {
    assert_eq!(effective_limit(MAX_QUERY_LIMIT + 1), MAX_QUERY_LIMIT);
}

#[test]
fn effective_limit_normal_value_unchanged() {
    assert_eq!(effective_limit(50), 50);
    assert_eq!(effective_limit(1), 1);
    assert_eq!(effective_limit(DEFAULT_QUERY_LIMIT), DEFAULT_QUERY_LIMIT);
}

// ---- split_local_type boundary tests ----

#[test]
fn split_local_type_text() {
    let (msg_type, sub_type) = split_local_type(1_i64);
    assert_eq!(msg_type, 1);
    assert_eq!(sub_type, 0);
}

#[test]
fn split_local_type_app_with_sub_type() {
    // local_type = (5 << 32) | 49 — canonical low32/high32 encoding
    let local_type: i64 = (5_i64 << 32) | 49;
    let (msg_type, sub_type) = split_local_type(local_type);
    assert_eq!(msg_type, 49);
    assert_eq!(sub_type, 5);
}

#[test]
fn split_local_type_zero() {
    let (msg_type, sub_type) = split_local_type(0_i64);
    assert_eq!(msg_type, 0);
    assert_eq!(sub_type, 0);
}

#[test]
fn split_local_type_wechat_4x_quote() {
    // WeChat 4.x: quote reply, local_type = (57 << 32) | 49
    let local_type: i64 = (57_i64 << 32) | 49;
    let (msg_type, sub_type) = split_local_type(local_type);
    assert_eq!(msg_type, 49);
    assert_eq!(sub_type, 57);
}

// ---- msg_sub_type_label tests ----

#[test]
fn msg_sub_type_label_app_link() {
    assert_eq!(msg_sub_type_label(MSG_TYPE_APP, 5), "link");
}

#[test]
fn msg_sub_type_label_app_quote() {
    assert_eq!(msg_sub_type_label(MSG_TYPE_APP, 57), "quote");
}

#[test]
fn msg_sub_type_label_app_transfer() {
    assert_eq!(msg_sub_type_label(MSG_TYPE_APP, 2000), "transfer");
}

#[test]
fn msg_sub_type_label_app_group_announcement() {
    assert_eq!(msg_sub_type_label(MSG_TYPE_APP, 87), "group_announcement");
}

#[test]
fn msg_sub_type_label_app_unknown_fallback() {
    assert_eq!(msg_sub_type_label(MSG_TYPE_APP, 9999), "app");
}

#[test]
fn msg_sub_type_label_non_app_type() {
    assert_eq!(msg_sub_type_label(MSG_TYPE_TEXT, 0), "text");
}

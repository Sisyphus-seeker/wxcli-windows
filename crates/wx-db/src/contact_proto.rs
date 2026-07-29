use prost::Message;

// --- Protobuf structs for extra_buffer ---

#[derive(prost::Message)]
pub(crate) struct ContactExtraBufferProto {
    #[prost(uint32, optional, tag = "2")]
    pub gender: Option<u32>,
    #[prost(string, optional, tag = "4")]
    pub signature: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub country: Option<String>,
    #[prost(string, optional, tag = "6")]
    pub province: Option<String>,
    #[prost(string, optional, tag = "7")]
    pub city: Option<String>,
    #[prost(uint32, optional, tag = "8")]
    pub source_scene: Option<u32>,
    #[prost(message, optional, tag = "14")]
    pub phone_entry: Option<PhoneEntryProto>,
    #[prost(string, optional, tag = "30")]
    pub label_ids_csv: Option<String>,
}

#[derive(prost::Message)]
pub(crate) struct PhoneEntryProto {
    #[prost(uint32, optional, tag = "1")]
    pub has_phone: Option<u32>,
    #[prost(message, optional, tag = "2")]
    pub phone_detail: Option<PhoneDetailProto>,
}

#[derive(prost::Message)]
pub(crate) struct PhoneDetailProto {
    #[prost(string, optional, tag = "1")]
    pub number: Option<String>,
}

// --- Decoded intermediate type ---

#[derive(Default)]
pub(crate) struct ContactExtra {
    pub gender: Option<u32>,
    pub signature: Option<String>,
    pub region: Option<String>,
    pub source_scene: Option<u32>,
    pub phone: Option<String>,
    pub label_ids: Vec<String>,
}

// --- Decode function ---

pub(crate) fn decode_extra_buffer(blob: &[u8]) -> ContactExtra {
    let proto = match ContactExtraBufferProto::decode(blob) {
        Ok(p) => p,
        Err(_) => return ContactExtra::default(),
    };

    let gender = proto.gender.filter(|&v| v > 0);

    let signature = proto.signature.filter(|s| !s.is_empty());

    let region = {
        let parts: Vec<&str> = [
            proto.country.as_deref(),
            proto.province.as_deref(),
            proto.city.as_deref(),
        ]
        .iter()
        .filter_map(|p| p.filter(|s| !s.is_empty()))
        .collect();
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" · "))
        }
    };

    let source_scene = proto.source_scene.filter(|&v| v > 0);

    let phone = proto
        .phone_entry
        .filter(|pe| pe.has_phone == Some(1))
        .and_then(|pe| pe.phone_detail)
        .and_then(|pd| pd.number)
        .filter(|n| !n.is_empty());

    let label_ids = proto
        .label_ids_csv
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    ContactExtra {
        gender,
        signature,
        region,
        source_scene,
        phone,
        label_ids,
    }
}

// --- Test encode helper ---

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn encode_extra_buffer_for_test(
    gender: Option<u32>,
    signature: Option<&str>,
    country: Option<&str>,
    province: Option<&str>,
    city: Option<&str>,
    source_scene: Option<u32>,
    phone: Option<&str>,
    label_ids_csv: Option<&str>,
) -> Vec<u8> {
    let phone_entry = phone.map(|number| PhoneEntryProto {
        has_phone: Some(1),
        phone_detail: Some(PhoneDetailProto {
            number: Some(number.to_string()),
        }),
    });

    let proto = ContactExtraBufferProto {
        gender,
        signature: signature.map(|s| s.to_string()),
        country: country.map(|s| s.to_string()),
        province: province.map(|s| s.to_string()),
        city: city.map(|s| s.to_string()),
        source_scene,
        phone_entry,
        label_ids_csv: label_ids_csv.map(|s| s.to_string()),
    };
    proto.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_all_fields() {
        let blob = encode_extra_buffer_for_test(
            Some(1),
            Some("hello world"),
            Some("CN"),
            Some("Beijing"),
            Some("Haidian"),
            Some(30),
            Some("13800138000"),
            Some("5,6"),
        );
        let extra = decode_extra_buffer(&blob);
        assert_eq!(extra.gender, Some(1));
        assert_eq!(extra.signature.as_deref(), Some("hello world"));
        assert_eq!(extra.region.as_deref(), Some("CN · Beijing · Haidian"));
        assert_eq!(extra.source_scene, Some(30));
        assert_eq!(extra.phone.as_deref(), Some("13800138000"));
        assert_eq!(extra.label_ids, vec!["5", "6"]);
    }

    #[test]
    fn decode_empty_blob() {
        let extra = decode_extra_buffer(&[]);
        assert_eq!(extra.gender, None);
        assert_eq!(extra.signature, None);
        assert_eq!(extra.region, None);
        assert_eq!(extra.source_scene, None);
        assert_eq!(extra.phone, None);
        assert!(extra.label_ids.is_empty());
    }

    #[test]
    fn decode_country_only() {
        let blob =
            encode_extra_buffer_for_test(None, None, Some("CN"), None, None, None, None, None);
        let extra = decode_extra_buffer(&blob);
        assert_eq!(extra.region.as_deref(), Some("CN"));
        assert_eq!(extra.gender, None);
        assert_eq!(extra.signature, None);
        assert_eq!(extra.source_scene, None);
        assert_eq!(extra.phone, None);
        assert!(extra.label_ids.is_empty());
    }
}

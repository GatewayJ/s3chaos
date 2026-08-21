use super::*;

pub(super) const CASES: &[ProtocolCase] = &[
    compatibility_case(COMPAT_BUCKET_HEAD, ProtocolDomain::Bucket),
    compatibility_case(COMPAT_BUCKET_LIST_CREATE_DELETE, ProtocolDomain::Bucket),
    compatibility_case(COMPAT_LIST_OBJECTS_BASIC, ProtocolDomain::Listing),
    compatibility_case(COMPAT_MULTI_OBJECT_DELETE, ProtocolDomain::CopyDelete),
    compatibility_case(COMPAT_MULTIPART_UPLOAD_SMALL, ProtocolDomain::Multipart),
    compatibility_case(COMPAT_OBJECT_COPY_SAME_BUCKET, ProtocolDomain::CopyDelete),
    compatibility_case(COMPAT_OBJECT_PUT_GET_DELETE, ProtocolDomain::Object),
    ProtocolCase {
        variants: NO_SUCH_KEY_VARIANTS,
        ..compatibility_versioning_case()
    },
];

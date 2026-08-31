use std::sync::LazyLock;

use crate::binary::schema::typed_header;

pub const PROJECT_HEADER: [u8; 8] = [0x66, 0x85, 0x82, 0x80, 0, 0, 0, 1];
pub const ALLOCATION_MARK: u64 = 56;
pub const ROOT_OFFSET: u64 = 0xFC;
pub const ROOT_TYPE_ID: u16 = 7;
pub const ROOT_HISTORY_TAG: u8 = 1;
pub const ROW_TYPE_ID: u16 = 1;

pub const ROW: [(u8, u16); 31] = [
    (127, 97),
    (0, 101),
    (1, 105),
    (2, 113),
    (3, 121),
    (4, 129),
    (5, 137),
    (6, 138),
    (7, 140),
    (8, 142),
    (9, 146),
    (10, 154),
    (11, 162),
    (13, 170),
    (14, 171),
    (15, 175),
    (16, 183),
    (17, 191),
    (18, 199),
    (19, 207),
    (20, 215),
    (21, 223),
    (22, 231),
    (23, 239),
    (24, 247),
    (25, 248),
    (26, 249),
    (27, 250),
    (28, 258),
    (29, 266),
    (30, 274),
];

pub const ROW_WIDTHS: [(u8, u8); 31] = [
    (127, 4),
    (0, 4),
    (1, 8),
    (2, 8),
    (3, 8),
    (4, 8),
    (5, 1),
    (6, 2),
    (7, 2),
    (8, 4),
    (9, 8),
    (10, 8),
    (11, 8),
    (13, 1),
    (14, 4),
    (15, 8),
    (16, 8),
    (17, 8),
    (18, 8),
    (19, 8),
    (20, 8),
    (21, 8),
    (22, 8),
    (23, 8),
    (24, 1),
    (25, 1),
    (26, 1),
    (27, 8),
    (28, 8),
    (29, 8),
    (30, 8),
];

pub static ROW_HEADER: LazyLock<Vec<u8>> = LazyLock::new(|| typed_header(ROW_TYPE_ID, &ROW));

pub const HISTORY_LIST: [(u8, u16); 6] = [(0, 22), (1, 30), (2, 38), (3, 46), (4, 54), (5, 58)];
pub const CHUNKING: [(u8, u16); 4] = [(0, 16), (1, 20), (2, 24), (3, 32)];
pub const TABLE: [(u8, u16); 2] = [(0, 10), (1, 14)];
pub const REQUEST_METADATA: [(u8, u16); 6] = [(0, 22), (1, 30), (2, 38), (3, 42), (4, 46), (5, 54)];
pub const SERVICE: [(u8, u16); 7] = [
    (0, 25),
    (1, 33),
    (2, 37),
    (3, 38),
    (4, 39),
    (5, 47),
    (6, 55),
];
pub const HOST_WRAPPER: [(u8, u16); 2] = [(0, 10), (1, 18)];
pub const TEXT_WRAPPER: [(u8, u16); 2] = [(0, 10), (1, 18)];
pub const COMMENT_WRAPPER: [(u8, u16); 2] = [(1, 10), (2, 18)];
pub const COMMENT_CHUNK: [(u8, u16); 3] = [(1, 13), (2, 21), (3, 25)];

pub mod tag {
    pub const ENTRY_ID: u8 = 0;
    pub const METHOD: u8 = 1;
    pub const REQUEST_METADATA: u8 = 2;
    pub const EXTENSION: u8 = 3;
    pub const IP: u8 = 4;
    pub const STATUS_CODE: u8 = 6;
    pub const MIME_CODE: u8 = 7;
    pub const RESPONSE_LENGTH: u8 = 8;
    pub const TITLE: u8 = 9;
    pub const COOKIES: u8 = 10;
    pub const TIME_EPOCH_MS: u8 = 11;
    pub const HIGHLIGHT: u8 = 13;
    pub const LISTENER_PORT: u8 = 14;
    pub const REQUEST_FRAME: u8 = 15;
    pub const RESPONSE_FRAME: u8 = 18;
    pub const COMMENT_WRAPPER: u8 = 27;
    pub const TIMING_1: u8 = 28;
    pub const TIMING_2: u8 = 29;
    pub const SECONDARY_TIME: u8 = 30;
}

pub const ROW_MAGIC: u64 = 0x7A13_353F;
pub const ROW_TAG24: u64 = 1;
pub const ROW_TAG25: u64 = 0xFF;
pub const ROW_TAG26: u64 = 0xFF;
pub const SERVICE_TAG3: u64 = 4;
pub const SERVICE_TAG6: u64 = 8_123_178_716_164_521_984;
pub const METADATA_SENTINEL: u64 = 0xFFFF_FFFF;
pub const MIME_HTML: u64 = 0x0100;
pub const MIME_TEXT: u64 = 0x0101;
pub const MIME_CSS: u64 = 0x0102;
pub const MIME_SCRIPT: u64 = 0x0103;
pub const MIME_JSON: u64 = 0x0104;
pub const MIME_XML: u64 = 0x0106;

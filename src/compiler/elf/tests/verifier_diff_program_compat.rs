mod nu_support;
mod parser_support;
mod rust_support;
mod source_support;

use nu_support::*;
use parser_support::*;
use rust_support::*;
use source_support::*;

mod context_field_metadata_tests;
mod context_read_scanner_tests;
mod context_write_scanner_tests;
mod iter_metadata_tests;
mod map_metadata_tests;
mod metadata_tests;
mod program_feature_scanner_tests;
mod program_helper_scanner_tests;
mod program_kfunc_scanner_tests;
mod program_struct_ops_scanner_tests;
mod program_surface_scanner_tests;
mod runtime_tests;
mod source_tests;

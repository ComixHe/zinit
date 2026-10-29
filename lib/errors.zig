// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The error vocabulary, split by layer: parsing explains a rejected command
//! line, the runtime has one syscall failure class, and the entry point sees the
//! union of both.

pub const ConfigError = error{
    InvalidSignal,
    InvalidParams,
    MissingCommand,
    InvalidRewrite,
    InvalidExitCode,
    DuplicateSignal,
    CycleRewrite,
};

pub const SysCallError = error{SysCallError};

pub const ZinitError = ConfigError || SysCallError;

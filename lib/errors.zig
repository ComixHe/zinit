// SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
//
// SPDX-License-Identifier: MIT

//! The error set every layer returns.

pub const ZinitError = error{
    InvalidSignal,
    InvalidParams,
    MissingCommand,
    InvalidRewrite,
    InvalidExitCode,
    SysCallError,
    DuplicateSignal,
    CycleRewrite,
};

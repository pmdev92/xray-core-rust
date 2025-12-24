package com.xray.core.rust

class InitCore private constructor() {

    private external fun initXrayRustCore()

    companion object {
        fun init() {
            InitCore()
        }
    }

    init {
        System.loadLibrary("xray_ffi_android")
        initXrayRustCore()
    }
}

public fun initialize() {
    InitCore.init()
}
use ::core::arch::asm;

struct Trainer {
    is_show_ui: bool,
    立即击晕: ByteHook,
    永不坠落: ByteHook,
    闪现无硬直: ByteHook,
    闪现距离: AsmHook,
    闪现无动画: AsmHook,
    闪现无CD: AsmHook,
    无限法力: AsmHook,
    无限暂停时间: AsmHook,
}

#[derive(Default)]
struct AsmHook {
    target_addr: usize,
    is_enabled: bool,
}

#[derive(Default)]
struct ByteHook {
    target_addr: usize,
    is_enabled: bool,
    source_opcode: Vec<u8>,
    patch_opcode: Vec<u8>,
}

impl AsmHook {
    unsafe fn create(
        &mut self,
        mod_addr: usize,
        mod_size: usize,
        sig: &str,
        opcode_size: usize,
        jmp_original_addr: usize,
    ) -> ::core::option::Option<()> {
        self.target_addr = libmem::sig_scan(sig, mod_addr, mod_size)?;

        let 原指令的下一指令地址 = self.target_addr + opcode_size;

        let mut 扫描结束的偏移 = 0;

        for i in 0..0xFF {
            let ptr = (jmp_original_addr + i) as *const u8;

            if ptr.read() == 0x90 {
                let parts = std::slice::from_raw_parts(ptr, 4);

                if parts.iter().all(|nop| *nop == 0x90) {
                    扫描结束的偏移 = i;
                    break;
                }
            }
        }

        let mut 远跳转指令 = Vec::new();

        远跳转指令.push(0xFF);
        远跳转指令.push(0x25);
        远跳转指令.push(0x0);
        远跳转指令.push(0x0);
        远跳转指令.push(0x0);
        远跳转指令.push(0x0);

        远跳转指令.extend_from_slice((原指令的下一指令地址 as isize).to_le_bytes().as_ref());

        libmem::write_memory_ex(
            &libmem::get_process().unwrap(),
            jmp_original_addr + 扫描结束的偏移,
            远跳转指令.as_slice(),
        )?;

        if hudhook::mh::MH_CreateHook(
            self.target_addr as *mut ::core::ffi::c_void,
            jmp_original_addr as *mut ::core::ffi::c_void,
            ::core::ptr::null_mut(),
        ) != hudhook::mh::MH_STATUS::MH_OK
        {
            return None;
        }

        Some(())
    }

    unsafe fn switch(&mut self) {
        if !self.is_enabled {
            let _ = hudhook::mh::MH_DisableHook(self.target_addr as *mut core::ffi::c_void);

            return;
        }

        let _ = hudhook::mh::MH_EnableHook(self.target_addr as *mut core::ffi::c_void);
    }
}

impl ByteHook {
    unsafe fn create(
        &mut self,
        mod_addr: usize,
        mod_size: usize,
        sig: &str,
        patch_code: Vec<u8>,
        target_addr_offset: isize,
    ) {
        let target_addr_temp = libmem::sig_scan(sig, mod_addr, mod_size).unwrap();

        self.target_addr = (target_addr_temp as isize + target_addr_offset) as usize;

        self.patch_opcode = patch_code;

        self.source_opcode.resize(self.patch_opcode.len(), 0);

        ::core::ptr::copy(
            self.target_addr as *const u8,
            self.source_opcode.as_mut_ptr(),
            self.patch_opcode.len(),
        );
    }

    unsafe fn switch(&mut self) {
        if self.is_enabled {
            let _ = libmem::memory::write_memory_ex(
                &libmem::process::get_process().unwrap(),
                self.target_addr,
                self.patch_opcode.as_slice(),
            );
        } else {
            let _ = libmem::memory::write_memory_ex(
                &libmem::process::get_process().unwrap(),
                self.target_addr,
                self.source_opcode.as_slice(),
            );
        }
    }
}

impl Trainer {
    unsafe fn on_frame(&mut self, ui: &hudhook::imgui::Ui) {
        if ui.checkbox("无限法力", &mut self.无限法力.is_enabled) {
            self.无限法力.switch()
        }

        if ui.checkbox("无限暂停时间", &mut self.无限暂停时间.is_enabled) {
            self.无限暂停时间.switch()
        }

        if ui.checkbox("立即击晕", &mut self.立即击晕.is_enabled) {
            self.立即击晕.switch()
        }

        if ui.checkbox("永不坠落", &mut self.永不坠落.is_enabled) {
            self.永不坠落.switch()
        }

        if ui.checkbox("闪现距离", &mut self.闪现距离.is_enabled) {
            self.闪现距离.switch()
        }

        if ui.checkbox("闪现无CD", &mut self.闪现无CD.is_enabled) {
            self.闪现无CD.switch()
        }

        if ui.checkbox("闪现无硬直", &mut self.闪现无硬直.is_enabled) {
            self.闪现无硬直.switch()
        }

        if ui.checkbox("闪现无动画", &mut self.闪现无动画.is_enabled) {
            self.闪现无动画.switch()
        }
    }
}

impl hudhook::ImguiRenderLoop for Trainer {
    fn initialize<'a>(
        &'a mut self,
        _ctx: &mut hudhook::imgui::Context,
        _render_context: &'a mut dyn hudhook::RenderContext,
    ) {
        _ctx.set_ini_filename(None);
        _ctx.style_mut().use_light_colors();

        unsafe {
            hudhook::imgui::sys::ImFontAtlas_AddFontFromFileTTF(
                hudhook::imgui::internal::RawCast::raw_mut(_ctx.fonts()),
                "C:\\windows\\fonts\\simhei.ttf\0".as_ptr().cast(),
                26.0,
                std::ptr::null(),
                hudhook::imgui::sys::ImFontAtlas_GetGlyphRangesChineseFull(
                    hudhook::imgui::internal::RawCast::raw_mut(_ctx.fonts()),
                ),
            )
        };
    }

    fn before_render<'a>(
        &'a mut self,
        _ctx: &mut hudhook::imgui::Context,
        _render_context: &'a mut dyn hudhook::RenderContext,
    ) {
        unsafe {
            static mut WAS_KEY_DOWN: bool = false;

            if (hudhook::windows::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState(
                hudhook::windows::Win32::UI::Input::KeyboardAndMouse::VK_OEM_3.0 as i32,
            ) as u16
                & 0x8000)
                != 0
            {
                if !WAS_KEY_DOWN {
                    WAS_KEY_DOWN = true;

                    self.is_show_ui = !self.is_show_ui;
                }
            } else if WAS_KEY_DOWN {
                WAS_KEY_DOWN = false;
            }

            if !self.is_show_ui {
                _ctx.io_mut().mouse_draw_cursor = false;
                return;
            }

            _ctx.io_mut().mouse_draw_cursor = true;
        }
    }

    fn render(&mut self, ui: &mut hudhook::imgui::Ui) {
        unsafe {
            if !self.is_show_ui {
                return;
            }

            ui.window(format!("[~]键"))
                .title_bar(true)
                .size([600.0, 450.0], hudhook::imgui::Condition::FirstUseEver)
                .build(|| self.on_frame(ui));
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(
    h_module: isize,
    ul_reason_for_call: u32,
    _lp_reserved: *mut core::ffi::c_void,
) -> i32 {
    if ul_reason_for_call == 1 {
        std::thread::spawn(move || {
            let time_begin = ::std::time::Instant::now();
            loop {
                if time_begin.elapsed().as_secs() > 60 {
                    return;
                }

                ::std::thread::sleep(::std::time::Duration::from_secs(3));

                if let Some(mod_info) = libmem::find_module("XAudio2_9.dll") {
                    if mod_info.base != 0 {
                        break;
                    }
                }
            }

            let main_mod_info = libmem::module::find_module("Dishonored2.exe").unwrap();

            if hudhook::mh::MH_Initialize() != hudhook::mh::MH_STATUS::MH_OK {
                return;
            }

            let mut trainer = Trainer {
                is_show_ui: true,

                立即击晕: ByteHook::default(),
                永不坠落: ByteHook::default(),
                闪现无硬直: ByteHook::default(),
                闪现距离: AsmHook::default(),
                闪现无动画: AsmHook::default(),
                闪现无CD: AsmHook::default(),
                无限法力: AsmHook::default(),
                无限暂停时间: AsmHook::default(),
            };

            // trainer.立即击晕.create(
            //     main_mod_info.base,
            //     main_mod_info.size,
            //     "8B 53 24 85 D2 74 18",
            //     vec![0x77],
            //     -2,
            // );

            // trainer.闪现无硬直.create(
            //     main_mod_info.base,
            //     main_mod_info.size,
            //     "48 8B 41 10 48 8B 48 28 48 8B 81 90 00 00 00 48 85 C0 74 0E 48 8B 40 70 48 85 C0",
            //     vec![0x30, 0xC0, 0xC3, 0x90],
            //     0,
            // );

            // trainer.永不坠落.create(
            //     main_mod_info.base,
            //     main_mod_info.size,
            //     "89 46 24 F3 0F 10 45 80",
            //     vec![0x90, 0x90, 0x90],
            //     0,
            // );

            trainer.无限法力.create(
                main_mod_info.base,
                main_mod_info.size,
                "0F 2F D1 F3 0F 10 7B",
                8,
                unlimited_mana as usize,
            );

            // trainer.无限暂停时间.create(
            //     main_mod_info.base,
            //     main_mod_info.size,
            //     "F3 0F 11 7D 67 C7",
            //     5,
            //     bend_time as usize,
            // );

            // trainer.闪现距离.create(
            //     main_mod_info.base,
            //     main_mod_info.size,
            //     "83 F8 FF 7E 13 48 8D 14 80 48 8B 43 40 48 8B 48 48",
            //     5,
            //     blink_distance as usize,
            // );

            // trainer.闪现无动画.create(
            //     main_mod_info.base,
            //     main_mod_info.size,
            //     "F3 44 0F 10 5A 70 4C 8D 4D DB 48 8D 55 67",
            //     6,
            //     blink_instant as usize,
            // );

            // trainer.闪现无CD.create(
            //     main_mod_info.base,
            //     main_mod_info.size,
            //     "F3 0F 10 80 50 01 00 00 F3 0F 11 02 74 0C F3 0F 58 80 04 02 00 00",
            //     8,
            //     blink_no_cd as usize,
            // );

            if let Err(_) = ::hudhook::Hudhook::builder()
                .with::<hudhook::hooks::dx11::ImguiDx11Hooks>(trainer)
                .with_hmodule(hudhook::windows::Win32::Foundation::HINSTANCE(h_module))
                .build()
                .apply()
            {
                ::hudhook::eject();
            }
        });
    } else if ul_reason_for_call == 0 {
    }

    1
}

unsafe extern "system" fn unlimited_mana() {
    asm!(
        "
        movss xmm1, xmm3
        comiss xmm2, xmm1
        movss xmm7, [rbx + 0x20]
        ",
        options(nomem, nostack)
    );

    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        options(nomem, nostack, noreturn)
    );
}

static mut TIME: f32 = f32::MAX;
unsafe extern "system" fn bend_time() {
    asm!("push rax", options(nomem, nostack));

    asm!(
        "
        movss xmm7, [rax]
        ",

        in("rax") std::ptr::addr_of_mut!(TIME),
        options(nomem,nostack)
    );

    asm!("pop rax", options(nomem, nostack));

    asm!("movss [rbp + 0x67], xmm7", options(nomem, nostack));

    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        options(nomem, nostack, noreturn)
    );
}

static mut BLINK_DISTANCE_FAR: f32 = 60.0;
static mut BLINK_DISTANCE_NEAR: f32 = 20.0;

unsafe extern "system" fn blink_distance() {
    asm!("push rax", options(nomem, nostack));
    asm!("push rdx", options(nomem, nostack));

    asm!("cmp eax, -1", options(nomem, nostack));

    asm!(
        "
        jle short 2f
        movss xmm8, [rax]
        2:
        movss xmm4, [r15]
        ",

        in("rax") std::ptr::addr_of_mut!(BLINK_DISTANCE_FAR),
        in("rdx") std::ptr::addr_of_mut!(BLINK_DISTANCE_NEAR),
        options(nomem,nostack)
    );

    asm!("pop rdx", options(nomem, nostack));
    asm!("pop rax", options(nomem, nostack));

    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        options(nomem, nostack, noreturn)
    );
}

static mut BLINK_INSTANT: f32 = 0.0;
unsafe extern "system" fn blink_instant() {
    asm!("push rax", options(nomem, nostack));

    asm!(
        "
        movss xmm11, [rax]
        ",

        in("rax") std::ptr::addr_of_mut!(BLINK_INSTANT),

        options(nomem,nostack)
    );

    asm!("pop rax", options(nomem, nostack));

    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        options(nomem, nostack, noreturn)
    );
}

unsafe extern "system" fn blink_no_cd() {
    asm!(
        "
        mov dword ptr [rdx], 0
        mov rax, rdx
        ret
        ",
        options(nomem, nostack)
    );

    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        options(nomem, nostack, noreturn)
    );
}

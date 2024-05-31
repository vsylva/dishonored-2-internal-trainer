use hudhook::imgui::{
    internal::RawCast,
    sys::{ImFontAtlas_AddFontFromFileTTF, ImFontAtlas_GetGlyphRangesChineseFull},
};

use crate::hook::{
    BLINK_NO_ANIMATION, HOOK_BEND_TIME, HOOK_BLINK_DISTANCE, HOOK_BLINK_NO_CD,
    HOOK_BLINK_NO_HIT_STUN, HOOK_INSTANT_CHOKE, HOOK_NEVER_FALL, HOOK_UNLIMITED_MANA,
};

pub static mut IS_SHOW_UI: bool = true;

pub unsafe fn on_frame(ui: &hudhook::imgui::Ui) {
    if ui.checkbox("无限法力", &mut HOOK_UNLIMITED_MANA.is_enabled) {
        HOOK_UNLIMITED_MANA.switch()
    }

    if ui.checkbox("无限暂停时间", &mut HOOK_BEND_TIME.is_enabled) {
        HOOK_BEND_TIME.switch()
    }

    if ui.checkbox("立即击晕", &mut HOOK_INSTANT_CHOKE.is_enabled) {
        HOOK_INSTANT_CHOKE.switch()
    }

    if ui.checkbox("永不坠落", &mut HOOK_NEVER_FALL.is_enabled) {
        HOOK_NEVER_FALL.switch()
    }

    if ui.checkbox("闪现距离", &mut HOOK_BLINK_DISTANCE.is_enabled) {
        HOOK_BLINK_DISTANCE.switch()
    }

    if ui.checkbox("闪现无CD", &mut HOOK_BLINK_NO_CD.is_enabled) {
        HOOK_BLINK_NO_CD.switch()
    }

    if ui.checkbox("闪现无硬直", &mut HOOK_BLINK_NO_HIT_STUN.is_enabled) {
        HOOK_BLINK_NO_HIT_STUN.switch()
    }

    if ui.checkbox("闪现无动画", &mut BLINK_NO_ANIMATION.is_enabled) {
        BLINK_NO_ANIMATION.switch()
    }
}

pub struct RenderLoop;

impl hudhook::ImguiRenderLoop for RenderLoop {
    fn initialize<'a>(
        &'a mut self,
        _ctx: &mut hudhook::imgui::Context,
        _render_context: &'a mut dyn hudhook::RenderContext,
    ) {
        _ctx.set_ini_filename(None);

        unsafe {
            ImFontAtlas_AddFontFromFileTTF(
                _ctx.fonts().raw_mut(),
                "C:\\windows\\fonts\\simhei.ttf\0".as_ptr().cast(),
                26.0,
                std::ptr::null(),
                ImFontAtlas_GetGlyphRangesChineseFull(_ctx.fonts().raw_mut()),
            )
        };

        _ctx.style_mut().use_light_colors();
    }

    fn before_render<'a>(
        &'a mut self,
        _ctx: &mut hudhook::imgui::Context,
        _render_context: &'a mut dyn hudhook::RenderContext,
    ) {
        unsafe {
            static mut WAS_KEY_DOWN: bool = false;

            if (crate::GetAsyncKeyState(0x2D) & 0x8000) != 0 {
                if !WAS_KEY_DOWN {
                    WAS_KEY_DOWN = true;

                    IS_SHOW_UI = !IS_SHOW_UI;
                }
            } else if WAS_KEY_DOWN {
                WAS_KEY_DOWN = false;
            }

            if !IS_SHOW_UI {
                _ctx.io_mut().mouse_draw_cursor = false;
                return;
            }

            _ctx.io_mut().mouse_draw_cursor = true;
        }
    }

    fn render(&mut self, ui: &mut hudhook::imgui::Ui) {
        unsafe {
            if !IS_SHOW_UI {
                return;
            }

            ui.window(format!("[Insert]键"))
                .title_bar(true)
                .size([600.0, 450.0], hudhook::imgui::Condition::FirstUseEver)
                .build(|| on_frame(ui));
        }
    }
}

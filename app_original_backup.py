"""
Chulabhorn Pharmaceutical Manufacturing Facility
Plant Access Management System
--------------------------------
Streamlit application with:
- iOS / Liquid Glass inspired UI
- SQLite WAL mode and transactional updates
- Role-based authentication using Streamlit secrets
- Safer secret handling (no passwords/API keys in source code)
- Visitor registration and document upload
- Two independent initial approvals + final approval
- Approval/rejection notifications
- PDF access-pass generation with Thai font support
- Dashboard metrics, filtering, search and audit trail
- Defensive validation and error handling
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import shutil
import psycopg
from psycopg.rows import dict_row
import smtplib
import time
import uuid
from contextlib import contextmanager
from datetime import date, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Optional, Any

import pandas as pd
import streamlit as st
from fpdf import FPDF


# ============================================================
# 0. APPLICATION CONFIGURATION
# ============================================================

APP_NAME = "Chulabhorn Pharmaceutical Manufacturing Facility"
APP_TITLE = "Plant's Area Access Management"
DB_PATH = Path("data/plant_access.db")
UPLOAD_DIR = Path("uploads")
GENERATED_DIR = Path("generated")
MAX_UPLOAD_MB = 15

ALLOWED_UPLOAD_TYPES = ["pdf", "jpg", "jpeg", "png", "docx"]
ALLOWED_UPLOAD_EXTENSIONS = {f".{x}" for x in ALLOWED_UPLOAD_TYPES}

VISIT_REASONS = [
    "Routine Maintenance",
    "Regulatory Audit",
    "Vendor Meeting",
    "Contractor Work",
    "Training / Inspection",
    "Other",
]

ACCESS_ZONES = [
    "General Office",
    "Warehouse",
    "Packaging",
    "Cleanroom (Gowning Required)",
    "QC Laboratory",
]

STATUS_LABELS = {
    "Pending Initial": "Awaiting initial approvals",
    "Pending Final": "Awaiting final approval",
    "Approved": "Approved",
    "Rejected": "Rejected",
}

ROLE_LABELS = {
    "approver1": "Initial Approver 1",
    "approver2": "Initial Approver 2",
    "final_approver": "Final Approver",
}


# ============================================================
# LANGUAGE
# ============================================================
TRANSLATIONS = {
    "English": {
        "app_subtitle": "Plant Access Management System", "secure": "SECURE WORKFLOW",
        "visitor_tab": "Visitor registration", "approval_tab": "Approval center", "admin_tab": "Administration",
        "visitor_title": "Request facility access", "visitor_subtitle": "A secure, auditable workflow for visitor, contractor and vendor access.",
        "approval_title": "Approval center", "approval_subtitle": "Review requests, supporting documents and approval history in one place.",
        "admin_title": "Administration", "admin_subtitle": "Manage approver accounts, email routing and system activity.",
        "visitor_kicker": "VISITOR PORTAL", "approval_kicker": "APPROVER WORKSPACE", "admin_kicker": "SYSTEM ADMINISTRATION",
        "language": "Language", "theme": "Appearance", "dark": "Dark", "light": "Light",
        "visitor_info": "Please submit complete and accurate information. Access to GMP-controlled areas is subject to facility approval and safety requirements.",
        "visitor_information": "Visitor information", "full_name": "Full name *", "company": "Company / organization *", "email": "Email address *", "visit_date": "Requested visit date *",
        "visit_details": "Visit details", "reason": "Reason for visit *", "zones": "Requested zones *", "other_reason": "Please specify the reason *", "other_placeholder": "Describe the purpose of the visit",
        "documents": "Supporting documentation", "upload": "Upload PDF / JPG / PNG / DOCX (maximum {mb} MB)", "safety": "Safety declaration",
        "safety_text": "I confirm that the visitor(s) will comply with facility safety, GMP, gowning and access-control requirements, and will not enter restricted areas without authorization. *",
        "submit": "Submit access request", "required": "Please complete all required visitor information and requested zones.", "valid_email": "Please enter a valid email address.",
        "specify_reason": "Please specify the reason for visiting.", "accept_safety": "The safety declaration must be accepted before submitting.", "past_date": "The visit date cannot be in the past.",
        "submitted": "Access request submitted successfully. Your request has entered the approval workflow.", "stored_email_warning": "The request is safely stored, but one or more notification emails could not be delivered. An administrator should check SMTP settings.",
        "unable_submit": "Unable to submit the request: {error}", "secure_signin": "Secure approver sign-in", "registered_email": "Registered approver email", "password": "Password", "signin": "Sign in", "signout": "Sign out",
        "enter_credentials": "Enter your email and password.", "invalid_credentials": "Invalid approver credentials.", "signed_in": "Signed in: {label} • {email}", "awaiting_initial": "Awaiting initial", "awaiting_final": "Awaiting final", "approved": "Approved", "rejected": "Rejected",
        "search_pending": "Search pending requests", "search_placeholder": "Visitor name, company, email or confirmation...", "no_pending": "No requests are currently waiting in your queue.",
        "pending": "Pending", "visitor": "Visitor", "company_label": "Company", "visit_date_label": "Visit date", "email_label": "Email", "reason_label": "Reason", "zones_label": "Zones", "health": "Health declaration", "status": "Status", "download_doc": "📄 Download supporting document", "no_doc": "No supporting document uploaded.",
        "rejection_reason": "Rejection reason", "rejection_placeholder": "Required when rejecting...", "approve": "✓ Approve", "reject": "✕ Reject", "enter_rejection": "Please enter a rejection reason.", "confirmation": "Confirmation: {id}", "request_id": "Request ID: {id}", "submitted_at": "Submitted: {time}",
        "approved_visitors": "Approved visitors", "approved_subtitle": "Use this list to confirm the confirmation ID when an approved visitor arrives at the facility.", "search_approved": "Search approved visitors", "approved_placeholder": "Confirmation ID, visitor name, company, email...", "no_approved": "No approved visitors match your search.", "arrival_confirm": "Confirmation ID", "visit": "Visit", "zones_requested": "Access zones", "visitor_email": "Visitor email", "view_pass": "View / download access pass", "arrival_note": "Ask the visitor to present this confirmation ID to the security or reception team.",
        "admin_active": "Administrator session active.", "admin_password": "Administrator password", "admin_signin": "Sign in as administrator", "invalid_admin": "Invalid administrator credentials.",
        "accounts_routing": "Approver accounts & email routing", "single_source": "These addresses are the single source of truth for both approver login and notification routing.", "email_field": "Email", "new_password": "New password", "leave_blank": "Leave blank", "active": "Active", "save_account": "Save account", "updated": "{label} updated.",
        "smtp": "SMTP configuration", "smtp_info": "SMTP credentials remain in .streamlit/secrets.toml so they are not stored in the application database.", "server": "Server", "sender": "Sender", "not_configured": "Not configured", "test_email_to": "Send test email to", "send_test": "Send test email", "enter_valid_recipient": "Enter a valid recipient email.", "test_success": "Test email sent successfully.",
        "monitoring": "Request monitoring", "status_filter": "Status", "all": "All", "search": "Search", "search_monitor_placeholder": "Name, company, email...", "no_matching": "No matching requests.", "audit": "Audit trail", "database_error": "Database initialization failed. Check that the application directory is writable.",
        "initial_1": "Initial Approver 1", "initial_2": "Initial Approver 2", "final_approver": "Final Approver",
        "routine": "Routine Maintenance", "audit_reason": "Regulatory Audit", "vendor": "Vendor Meeting", "contractor": "Contractor Work", "training": "Training / Inspection", "other": "Other",
        "general": "General Office", "warehouse": "Warehouse", "packaging": "Packaging", "cleanroom": "Cleanroom (Gowning Required)", "qc": "QC Laboratory",
        "email_not_configured": "Email notification is not configured. The request has still been saved successfully.", "email_failed": "Notification email could not be sent: {error}", "request_missing": "Request no longer exists.", "already_finalized": "This request has already been finalized.", "approval_recorded": "Approval recorded successfully.", "approval_already": "Your approval has already been recorded.", "not_ready_final": "This request is not ready for final approval.", "final_already": "Final approval has already been recorded.", "invalid_role": "Invalid approval role.", "rejected_success": "Request rejected.", "th_audit": "การตรวจประเมินด้านกฎระเบียบ", "th_vendor": "ประชุมกับผู้ขาย/คู่ค้า", "th_contractor": "งานผู้รับเหมา", "th_training": "ฝึกอบรม / ตรวจสอบ", "th_other": "อื่น ๆ",
    },
    "ไทย": {
        "app_subtitle": "ระบบบริหารจัดการการเข้า-ออกโรงงาน", "secure": "ระบบงานรักษาความปลอดภัย",
        "visitor_tab": "ลงทะเบียนผู้มาติดต่อ", "approval_tab": "ศูนย์อนุมัติ", "admin_tab": "ผู้ดูแลระบบ",
        "visitor_title": "ขออนุญาตเข้าโรงงาน", "visitor_subtitle": "ระบบคำขอเข้าโรงงานที่ปลอดภัย ตรวจสอบย้อนหลังได้ สำหรับผู้มาติดต่อ ผู้รับเหมา และคู่ค้า",
        "approval_title": "ศูนย์อนุมัติ", "approval_subtitle": "ตรวจสอบคำขอ เอกสารประกอบ และประวัติการอนุมัติได้ในที่เดียว",
        "admin_title": "ผู้ดูแลระบบ", "admin_subtitle": "จัดการบัญชีผู้อนุมัติ การส่งอีเมล และกิจกรรมของระบบ",
        "visitor_kicker": "พอร์ทัลผู้มาติดต่อ", "approval_kicker": "พื้นที่ทำงานสำหรับผู้อนุมัติ", "admin_kicker": "การดูแลระบบ",
        "language": "ภาษา", "theme": "รูปแบบการแสดงผล", "dark": "มืด", "light": "สว่าง",
        "visitor_info": "กรุณากรอกข้อมูลให้ครบถ้วนและถูกต้อง การเข้าเขตควบคุมตามหลัก GMP ต้องได้รับอนุมัติจากโรงงานและเป็นไปตามข้อกำหนดด้านความปลอดภัย",
        "visitor_information": "ข้อมูลผู้มาติดต่อ", "full_name": "ชื่อ-นามสกุล *", "company": "บริษัท / หน่วยงาน *", "email": "อีเมล *", "visit_date": "วันที่ขอเข้าพบ *",
        "visit_details": "รายละเอียดการเข้าพบ", "reason": "วัตถุประสงค์การเข้าพบ *", "zones": "พื้นที่ที่ต้องการเข้า *", "other_reason": "โปรดระบุวัตถุประสงค์ *", "other_placeholder": "ระบุวัตถุประสงค์การเข้าพบ",
        "documents": "เอกสารประกอบ", "upload": "อัปโหลด PDF / JPG / PNG / DOCX (ขนาดไม่เกิน {mb} MB)", "safety": "คำรับรองด้านความปลอดภัย",
        "safety_text": "ข้าพเจ้ารับทราบและยืนยันว่าผู้มาติดต่อจะปฏิบัติตามข้อกำหนดด้านความปลอดภัย GMP การแต่งกาย และการควบคุมการเข้า-ออก และจะไม่เข้าพื้นที่หวงห้ามโดยไม่ได้รับอนุญาต *",
        "submit": "ส่งคำขอเข้าโรงงาน", "required": "กรุณากรอกข้อมูลผู้มาติดต่อและพื้นที่ที่ต้องการเข้าให้ครบถ้วน", "valid_email": "กรุณากรอกอีเมลให้ถูกต้อง", "specify_reason": "กรุณาระบุวัตถุประสงค์การเข้าพบ", "accept_safety": "ต้องยอมรับคำรับรองด้านความปลอดภัยก่อนส่งคำขอ", "past_date": "วันที่เข้าพบต้องไม่เป็นวันที่ผ่านมาแล้ว",
        "submitted": "ส่งคำขอเข้าโรงงานเรียบร้อยแล้ว และคำขอเข้าสู่กระบวนการอนุมัติ", "stored_email_warning": "บันทึกคำขอเรียบร้อยแล้ว แต่ไม่สามารถส่งอีเมลแจ้งเตือนได้ครบถ้วน กรุณาให้ผู้ดูแลระบบตรวจสอบ SMTP",
        "unable_submit": "ไม่สามารถส่งคำขอได้: {error}", "secure_signin": "เข้าสู่ระบบสำหรับผู้อนุมัติ", "registered_email": "อีเมลผู้อนุมัติ", "password": "รหัสผ่าน", "signin": "เข้าสู่ระบบ", "signout": "ออกจากระบบ",
        "enter_credentials": "กรุณากรอกอีเมลและรหัสผ่าน", "invalid_credentials": "อีเมลหรือรหัสผ่านผู้อนุมัติไม่ถูกต้อง", "signed_in": "เข้าสู่ระบบ: {label} • {email}", "awaiting_initial": "รอการอนุมัติขั้นต้น", "awaiting_final": "รอการอนุมัติขั้นสุดท้าย", "approved": "อนุมัติแล้ว", "rejected": "ไม่อนุมัติ",
        "search_pending": "ค้นหาคำขอที่รออนุมัติ", "search_placeholder": "ชื่อผู้มาติดต่อ บริษัท อีเมล หรือ Confirmation ID...", "no_pending": "ไม่มีคำขอที่รอการอนุมัติในคิวของคุณ",
        "pending": "รอดำเนินการ", "visitor": "ผู้มาติดต่อ", "company_label": "บริษัท / หน่วยงาน", "visit_date_label": "วันที่เข้าพบ", "email_label": "อีเมล", "reason_label": "วัตถุประสงค์", "zones_label": "พื้นที่", "health": "คำรับรองด้านสุขภาพ", "status": "สถานะ", "download_doc": "📄 ดาวน์โหลดเอกสารประกอบ", "no_doc": "ไม่มีเอกสารประกอบ",
        "rejection_reason": "เหตุผลที่ไม่อนุมัติ", "rejection_placeholder": "ต้องระบุเมื่อไม่อนุมัติ...", "approve": "✓ อนุมัติ", "reject": "✕ ไม่อนุมัติ", "enter_rejection": "กรุณาระบุเหตุผลที่ไม่อนุมัติ", "confirmation": "Confirmation ID: {id}", "request_id": "รหัสคำขอ: {id}", "submitted_at": "ส่งคำขอเมื่อ: {time}",
        "approved_visitors": "รายชื่อผู้ได้รับอนุมัติ", "approved_subtitle": "ใช้รายการนี้เพื่อตรวจสอบ Confirmation ID ของผู้มาติดต่อที่ได้รับอนุมัติเมื่อเดินทางมาถึงโรงงาน", "search_approved": "ค้นหาผู้ได้รับอนุมัติ", "approved_placeholder": "Confirmation ID ชื่อผู้มาติดต่อ บริษัท อีเมล...", "no_approved": "ไม่พบผู้ได้รับอนุมัติที่ตรงกับการค้นหา", "arrival_confirm": "Confirmation ID", "visit": "การเข้าพบ", "zones_requested": "พื้นที่ที่ได้รับอนุมัติ", "visitor_email": "อีเมลผู้มาติดต่อ", "view_pass": "ดู / ดาวน์โหลดบัตรผ่าน", "arrival_note": "กรุณาให้ผู้มาติดต่อแสดง Confirmation ID ต่อเจ้าหน้าที่รักษาความปลอดภัยหรือเจ้าหน้าที่ต้อนรับ",
        "admin_active": "เซสชันผู้ดูแลระบบกำลังทำงาน", "admin_password": "รหัสผ่านผู้ดูแลระบบ", "admin_signin": "เข้าสู่ระบบผู้ดูแลระบบ", "invalid_admin": "รหัสผ่านผู้ดูแลระบบไม่ถูกต้อง",
        "accounts_routing": "บัญชีผู้อนุมัติและการกำหนดเส้นทางอีเมล", "single_source": "อีเมลเหล่านี้เป็นข้อมูลหลักที่ใช้ทั้งสำหรับการเข้าสู่ระบบของผู้อนุมัติและการส่งการแจ้งเตือน", "email_field": "อีเมล", "new_password": "รหัสผ่านใหม่", "leave_blank": "เว้นว่างเพื่อไม่เปลี่ยน", "active": "ใช้งาน", "save_account": "บันทึกบัญชี", "updated": "อัปเดต {label} เรียบร้อยแล้ว",
        "smtp": "การตั้งค่า SMTP", "smtp_info": "ข้อมูลรับรอง SMTP ยังคงอยู่ใน .streamlit/secrets.toml และจะไม่ถูกเก็บในฐานข้อมูลของระบบ", "server": "เซิร์ฟเวอร์", "sender": "ผู้ส่ง", "not_configured": "ยังไม่ได้ตั้งค่า", "test_email_to": "ส่งอีเมลทดสอบไปที่", "send_test": "ส่งอีเมลทดสอบ", "enter_valid_recipient": "กรุณากรอกอีเมลผู้รับที่ถูกต้อง", "test_success": "ส่งอีเมลทดสอบเรียบร้อยแล้ว",
        "monitoring": "ติดตามคำขอ", "status_filter": "สถานะ", "all": "ทั้งหมด", "search": "ค้นหา", "search_monitor_placeholder": "ชื่อ บริษัท อีเมล...", "no_matching": "ไม่พบคำขอที่ตรงกับเงื่อนไข", "audit": "บันทึกการตรวจสอบ", "database_error": "ไม่สามารถเริ่มต้นฐานข้อมูลได้ กรุณาตรวจสอบว่าสามารถเขียนไฟล์ในโฟลเดอร์ของระบบได้",
        "initial_1": "ผู้อนุมัติขั้นต้น 1", "initial_2": "ผู้อนุมัติขั้นต้น 2", "final_approver": "ผู้อนุมัติขั้นสุดท้าย",
        "routine": "งานบำรุงรักษาตามแผน", "audit_reason": "การตรวจประเมินด้านกฎระเบียบ", "vendor": "ประชุมกับผู้ขาย/คู่ค้า", "contractor": "งานผู้รับเหมา", "training": "ฝึกอบรม / ตรวจสอบ", "other": "อื่น ๆ",
        "general": "สำนักงานทั่วไป", "warehouse": "คลังสินค้า", "packaging": "บรรจุภัณฑ์", "cleanroom": "ห้องคลีนรูม (ต้องสวมชุด)", "qc": "ห้องปฏิบัติการ QC",
        "email_not_configured": "ยังไม่ได้ตั้งค่าการแจ้งเตือนทางอีเมล แต่ระบบได้บันทึกคำขอเรียบร้อยแล้ว", "email_failed": "ไม่สามารถส่งอีเมลแจ้งเตือนได้: {error}", "request_missing": "ไม่พบคำขอแล้ว", "already_finalized": "คำขอนี้ได้รับการดำเนินการเสร็จสิ้นแล้ว", "approval_recorded": "บันทึกการอนุมัติเรียบร้อยแล้ว", "approval_already": "มีการบันทึกการอนุมัติของคุณแล้ว", "not_ready_final": "คำขอนี้ยังไม่พร้อมสำหรับการอนุมัติขั้นสุดท้าย", "final_already": "มีการบันทึกการอนุมัติขั้นสุดท้ายแล้ว", "invalid_role": "บทบาทผู้อนุมัติไม่ถูกต้อง", "rejected_success": "ไม่อนุมัติคำขอเรียบร้อยแล้ว", "th_audit": "การตรวจประเมินด้านกฎระเบียบ", "th_vendor": "ประชุมกับผู้ขาย/คู่ค้า", "th_contractor": "งานผู้รับเหมา", "th_training": "ฝึกอบรม / ตรวจสอบ", "th_other": "อื่น ๆ",
    },
}


def current_language() -> str:
    return st.session_state.get("language", "English")

def tr(key: str, **kwargs) -> str:
    value = TRANSLATIONS[current_language()].get(key, TRANSLATIONS["English"].get(key, key))
    return value.format(**kwargs) if kwargs else value

def role_label(role: str) -> str:
    return {
        "approver1": tr("initial_1"),
        "approver2": tr("initial_2"),
        "final_approver": tr("final_approver"),
    }.get(role, role)

def status_label(status: str) -> str:
    return {
        "Pending Initial": tr("awaiting_initial"),
        "Pending Final": tr("awaiting_final"),
        "Approved": tr("approved"),
        "Rejected": tr("rejected"),
    }.get(status, status)

def reason_options() -> list[str]:
    return [tr("routine"), tr("audit_reason"), tr("vendor"), tr("contractor"), tr("training"), tr("other")]

REASON_KEYS = ["routine", "audit_reason", "vendor", "contractor", "training", "other"]
ZONE_KEYS = ["general", "warehouse", "packaging", "cleanroom", "qc"]

def zone_options() -> list[str]:
    return [tr(k) for k in ZONE_KEYS]

def english_reason(display: str) -> str:
    opts=reason_options()
    idx=opts.index(display)
    return VISIT_REASONS[idx]

def english_zone(display: str) -> str:
    opts=zone_options()
    idx=opts.index(display)
    return ACCESS_ZONES[idx]


# ============================================================
# 1. PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title=f"{APP_TITLE} | {APP_NAME}",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# 2. LIQUID GLASS UI
# ============================================================

def apply_liquid_glass_ui() -> None:
    st.markdown(
        """
        <style>
        :root {
            --glass: rgba(255,255,255,.075);
            --glass-strong: rgba(255,255,255,.12);
            --glass-border: rgba(255,255,255,.16);
            --text: #f7f9fc;
            --muted: #aab4c4;
            --accent: #69a8ff;
            --accent-2: #8d7dff;
            --success: #55d98b;
            --danger: #ff6b81;
        }

        .stApp {
            background:
                radial-gradient(circle at 8% 5%, rgba(91,145,255,.20), transparent 50%),
                radial-gradient(circle at 92% 15%, rgba(139,92,246,.18), transparent 25%),
                radial-gradient(circle at 50% 100%, rgba(43,179,170,.10), transparent 30%),
                linear-gradient(145deg, #07101d 0%, #0b1423 42%, #090d18 100%);
            background-attachment: fixed;
            color: var(--text);
        }

        [data-testid="stHeader"] {
            background: transparent !important;
        }

        [data-testid="stToolbar"] {
            visibility: hidden;
        }

        .block-container {
            max-width: 1500px;
            padding-top: 2.2rem;
            padding-bottom: 4rem;
        }

        h1, h2, h3, h4 {
            color: #fff !important;
            letter-spacing: -.025em;
        }

        p, label, .stMarkdown, .stCaption {
            color: #dce3ef;
        }

        .hero {
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,.16);
            border-radius: 30px;
            padding: 28px 32px;
            margin-bottom: 22px;
            background:
                linear-gradient(135deg, rgba(255,255,255,.13), rgba(255,255,255,.035)),
                rgba(12,22,39,.52);
            backdrop-filter: blur(28px) saturate(170%);
            -webkit-backdrop-filter: blur(28px) saturate(170%);
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,.16),
                0 24px 70px rgba(0,0,0,.28);
        }

        .hero:before {
            content: "";
            position: absolute;
            width: 320px;
            height: 320px;
            top: -180px;
            right: -80px;
            border-radius: 50%;
            background: rgba(91,145,255,.22);
            filter: blur(35px);
        }

        .hero-kicker {
            color: #9fc6ff;
            font-size: .78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .14em;
            margin-bottom: 7px;
        }

        .hero-title {
            color: #fff;
            font-size: clamp(1.9rem, 4vw, 3.2rem);
            font-weight: 760;
            line-height: 1.05;
            margin: 0;
        }

        .hero-subtitle {
            color: #b7c4d7;
            margin-top: 10px;
            font-size: 1rem;
            max-width: 850px;
        }

        .glass-card {
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 20px;
            background: linear-gradient(
                135deg,
                rgba(255,255,255,.10),
                rgba(255,255,255,.035)
            );
            backdrop-filter: blur(24px) saturate(165%);
            -webkit-backdrop-filter: blur(24px) saturate(165%);
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,.10),
                0 16px 50px rgba(0,0,0,.18);
        }

        [data-testid="stForm"],
        [data-testid="stExpander"],
        [data-testid="stMetric"] {
            border: 1px solid var(--glass-border) !important;
            border-radius: 22px !important;
            background: linear-gradient(
                135deg,
                rgba(255,255,255,.095),
                rgba(255,255,255,.025)
            ) !important;
            backdrop-filter: blur(22px) saturate(165%) !important;
            -webkit-backdrop-filter: blur(22px) saturate(165%) !important;
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,.10),
                0 15px 45px rgba(0,0,0,.18) !important;
        }

        [data-testid="stMetric"] {
            padding: 18px !important;
        }

        [data-testid="stMetricLabel"] {
            color: #aebbd0 !important;
        }

        [data-testid="stMetricValue"] {
            color: #fff !important;
        }

        input, textarea {
            color: #fff !important;
            caret-color: #fff !important;
        }

        .stTextInput input,
        .stTextArea textarea,
        .stDateInput input,
        .stNumberInput input {
            background: rgba(0,0,0,.22) !important;
            border: 1px solid rgba(255,255,255,.12) !important;
            border-radius: 15px !important;
        }

        div[data-baseweb="select"] > div {
            background: rgba(0,0,0,.22) !important;
            border: 1px solid rgba(255,255,255,.12) !important;
            border-radius: 15px !important;
        }

        [data-testid="stFileUploaderDropzone"] {
            background: rgba(0,0,0,.18) !important;
            border: 1px dashed rgba(255,255,255,.20) !important;
            border-radius: 18px !important;
        }

        .stButton > button,
        .stFormSubmitButton > button {
            border-radius: 15px !important;
            border: 1px solid rgba(255,255,255,.16) !important;
            background: linear-gradient(
                135deg,
                rgba(105,168,255,.38),
                rgba(141,125,255,.28)
            ) !important;
            color: white !important;
            font-weight: 650 !important;
            min-height: 42px;
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,.18),
                0 8px 24px rgba(55,105,190,.16);
            transition: .2s ease;
        }

        .stButton > button:hover,
        .stFormSubmitButton > button:hover {
            transform: translateY(-1px);
            border-color: rgba(255,255,255,.28) !important;
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,.22),
                0 12px 32px rgba(75,125,220,.26);
        }

        [data-testid="stTabs"] {
            margin-top: 12px;
        }

        [data-testid="stTabs"] [role="tablist"] {
            gap: 7px;
            padding: 7px;
            border: 1px solid rgba(255,255,255,.13);
            border-radius: 22px;
            background: rgba(255,255,255,.055);
            backdrop-filter: blur(25px) saturate(180%);
            -webkit-backdrop-filter: blur(25px) saturate(180%);
        }

        [data-testid="stTabs"] button {
            border-radius: 16px !important;
            padding: 9px 18px !important;
            color: #aebbd0 !important;
            border: 1px solid transparent !important;
        }

        [data-testid="stTabs"] button[aria-selected="true"] {
            color: #fff !important;
            background: linear-gradient(
                135deg,
                rgba(105,168,255,.55),
                rgba(141,125,255,.40)
            ) !important;
            border-color: rgba(255,255,255,.20) !important;
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,.22),
                0 7px 22px rgba(75,125,220,.20);
        }

        [data-testid="stDataFrame"] {
            border-radius: 18px;
            overflow: hidden;
        }

        .status-pill {
            display: inline-block;
            padding: 6px 11px;
            border-radius: 999px;
            font-size: .78rem;
            font-weight: 700;
            background: rgba(255,255,255,.09);
            border: 1px solid rgba(255,255,255,.13);
        }

        .small-muted {
            color: #96a5ba;
            font-size: .82rem;
        }

        hr {
            border-color: rgba(255,255,255,.10) !important;
        }

        @media (max-width: 900px) {
            .block-container {
                padding-left: 1rem;
                padding-right: 1rem;
            }
            .hero {
                padding: 22px;
                border-radius: 24px;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if st.session_state.get("theme", "dark") == "light":
        st.markdown("""
        <style>
        .stApp { background: radial-gradient(circle at 8% 5%, rgba(91,145,255,.14), transparent 50%), radial-gradient(circle at 92% 15%, rgba(139,92,246,.10), transparent 25%), linear-gradient(145deg, #eef4fb 0%, #f7f9fc 45%, #e8eef7 100%) !important; color: #172033 !important; }
        h1,h2,h3,h4 { color:#182238 !important; }
        p,label,.stMarkdown,.stCaption { color:#3c475b !important; }
        .hero { background:linear-gradient(135deg, rgba(255,255,255,.82), rgba(255,255,255,.56)), rgba(255,255,255,.66); border-color:rgba(20,40,70,.12); box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 24px 70px rgba(50,70,100,.13); }
        .hero-title { color:#182238 !important; } .hero-subtitle { color:#59667b !important; } .hero-kicker { color:#426ca8 !important; }
        .glass-card,[data-testid="stForm"],[data-testid="stExpander"],[data-testid="stMetric"] { background:linear-gradient(135deg,rgba(255,255,255,.86),rgba(245,248,252,.72)) !important; border-color:rgba(20,40,70,.12) !important; box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 15px 45px rgba(50,70,100,.10) !important; }
        [data-testid="stMetricLabel"] { color:#657187 !important; } [data-testid="stMetricValue"] { color:#172033 !important; }
        input,textarea { color:#172033 !important; caret-color:#172033 !important; }
        .stTextInput input,.stTextArea textarea,.stDateInput input,.stNumberInput input,div[data-baseweb="select"] > div { background:rgba(255,255,255,.78) !important; border-color:rgba(20,40,70,.13) !important; color:#172033 !important; }
        [data-testid="stFileUploaderDropzone"] { background:rgba(255,255,255,.65) !important; border-color:rgba(20,40,70,.18) !important; }
        [data-testid="stTabs"] [role="tablist"] { background:rgba(255,255,255,.58); border-color:rgba(20,40,70,.10); }
        [data-testid="stTabs"] button { color:#637086 !important; } [data-testid="stTabs"] button[aria-selected="true"] { color:#172033 !important; }
        .status-pill { color:#24405f !important; background:rgba(255,255,255,.62); border-color:rgba(20,40,70,.12); }
        .small-muted { color:#68758a !important; } hr { border-color:rgba(20,40,70,.10) !important; }
        </style>
        """, unsafe_allow_html=True)


def render_hero(title: str, subtitle: str, kicker: str = "SECURE FACILITY ACCESS") -> None:
    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-kicker">{kicker}</div>
            <div class="hero-title">{title}</div>
            <div class="hero-subtitle">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# 3. DATABASE - POSTGRESQL
# ============================================================

def db_config() -> dict:
    required = ("host", "port", "database", "user", "password")
    cfg = {}
    for key in required:
        value = secret_get(f"database.{key}", "")
        if value == "":
            raise RuntimeError(
                f"Missing database setting: database.{key}. Configure .streamlit/secrets.toml."
            )
        cfg[key] = value
    cfg["port"] = int(cfg["port"])
    cfg["sslmode"] = secret_get("database.sslmode", "prefer")
    cfg["connect_timeout"] = int(secret_get("database.connect_timeout", "10"))
    return cfg


@contextmanager
def db_connection():
    cfg = db_config()
    conn = psycopg.connect(
        host=cfg["host"], port=cfg["port"], dbname=cfg["database"],
        user=cfg["user"], password=cfg["password"], sslmode=cfg["sslmode"],
        connect_timeout=cfg["connect_timeout"], row_factory=dict_row,
    )
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_requests (
                id TEXT PRIMARY KEY,
                visitor_name TEXT NOT NULL,
                visitor_email TEXT NOT NULL,
                company TEXT NOT NULL,
                visit_date TEXT NOT NULL,
                reason TEXT NOT NULL,
                areas_needed TEXT NOT NULL,
                health_declaration TEXT NOT NULL,
                document_path TEXT DEFAULT '',
                status TEXT NOT NULL,
                app1_status TEXT NOT NULL,
                app2_status TEXT NOT NULL,
                final_status TEXT NOT NULL,
                rejection_reason TEXT DEFAULT '',
                timestamp TEXT NOT NULL,
                confirmation_number TEXT DEFAULT '',
                created_by_ip TEXT DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                role TEXT PRIMARY KEY,
                email TEXT NOT NULL DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                role TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY,
                request_id TEXT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT DEFAULT '',
                timestamp TEXT NOT NULL
            )
        """)
        defaults = {"approver1":"app1@plant.com", "approver2":"app2@plant.com", "final_approver":"final@plant.com"}
        for role, email in defaults.items():
            conn.execute("INSERT INTO settings(role,email) VALUES(%s,%s) ON CONFLICT(role) DO NOTHING", (role,email))
        creds = configured_credentials()
        for role in ("approver1", "approver2", "final_approver"):
            email = creds[role]["email"].strip().lower()
            password_hash = creds[role]["password"]
            if email and password_hash:
                conn.execute("""
                    INSERT INTO users(role,email,password_hash,active,updated_at)
                    VALUES(%s,%s,%s,TRUE,%s)
                    ON CONFLICT(role) DO NOTHING
                """, (role,email,password_hash,datetime.now().isoformat(timespec="seconds")))
                conn.execute("""
                    INSERT INTO settings(role,email) VALUES(%s,%s)
                    ON CONFLICT(role) DO UPDATE SET email=EXCLUDED.email
                """, (role,email))
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_status ON access_requests(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_visit_date ON access_requests(visit_date)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_confirmation ON access_requests(confirmation_number)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_log(request_id)")


def get_setting(role: str) -> str:
    with db_connection() as conn:
        row = conn.execute("SELECT email FROM users WHERE role=%s AND active=TRUE", (role,)).fetchone()
        if row: return str(row["email"])
        row = conn.execute("SELECT email FROM settings WHERE role=%s", (role,)).fetchone()
        return str(row["email"]) if row else ""


def save_setting(role: str, email: str) -> None:
    email=email.strip().lower()
    if not valid_email(email): raise ValueError("Invalid email address")
    with db_connection() as conn:
        conn.execute("UPDATE users SET email=%s,updated_at=%s WHERE role=%s", (email,datetime.now().isoformat(timespec="seconds"),role))
        conn.execute("INSERT INTO settings(role,email) VALUES(%s,%s) ON CONFLICT(role) DO UPDATE SET email=EXCLUDED.email", (role,email))


def get_users() -> list[dict]:
    with db_connection() as conn:
        return conn.execute("""
            SELECT role,email,active,updated_at FROM users
            ORDER BY CASE role WHEN 'approver1' THEN 1 WHEN 'approver2' THEN 2 WHEN 'final_approver' THEN 3 ELSE 99 END
        """).fetchall()


def update_user(role: str, email: str, password: Optional[str]=None, active: Optional[bool]=None) -> None:
    email=email.strip().lower()
    if not valid_email(email): raise ValueError("Invalid email address")
    with db_connection() as conn:
        fields=["email=%s","updated_at=%s"]
        values=[email,datetime.now().isoformat(timespec="seconds")]
        if password:
            fields.append("password_hash=%s"); values.append(make_password_hash(password))
        if active is not None:
            fields.append("active=%s"); values.append(bool(active))
        values.append(role)
        conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE role=%s", values)
        conn.execute("INSERT INTO settings(role,email) VALUES(%s,%s) ON CONFLICT(role) DO UPDATE SET email=EXCLUDED.email", (role,email))


def audit(request_id: Optional[str], actor: str, action: str, details: str="") -> None:
    with db_connection() as conn:
        conn.execute("""
            INSERT INTO audit_log(request_id,actor,action,details,timestamp)
            VALUES(%s,%s,%s,%s,%s)
        """, (request_id,actor,action,details,datetime.now().isoformat(timespec="seconds")))


# 4. SECURITY / AUTHENTICATION
# ============================================================

def secret_get(path: str, default: str = "") -> str:
    """
    Read nested Streamlit secrets safely.
    Example path: "auth.approver1.password"
    """
    try:
        value = st.secrets
        for part in path.split("."):
            value = value[part]
        return str(value)
    except Exception:
        return default


def password_digest(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        240_000,
    ).hex()


def verify_password(password: str, stored: str) -> bool:
    """
    Supports either:
    1) pbkdf2$<salt>$<digest>
    2) legacy plain value, only for migration convenience
    """
    if not stored:
        return False

    if stored.startswith("pbkdf2$"):
        try:
            _, salt, digest = stored.split("$", 2)
            calculated = password_digest(password, salt)
            return hmac.compare_digest(calculated, digest)
        except Exception:
            return False

    # Do not use this for new deployments. It allows a straightforward
    # migration from an existing plain secret to a hashed secret.
    return hmac.compare_digest(password, stored)


def make_password_hash(password: str) -> str:
    salt = secrets.token_bytes(16).hex()
    return f"pbkdf2${salt}${password_digest(password, salt)}"


def configured_credentials() -> dict:
    """
    Preferred secrets.toml structure:

    [auth]
    admin_password_hash = "pbkdf2$..."

    [auth.approver1]
    email = "approver1@facility.example"
    password_hash = "pbkdf2$..."

    [auth.approver2]
    email = "approver2@facility.example"
    password_hash = "pbkdf2$..."

    [auth.final_approver]
    email = "final@facility.example"
    password_hash = "pbkdf2$..."
    """
    return {
        "approver1": {
            "email": secret_get("auth.approver1.email"),
            "password": secret_get("auth.approver1.password_hash"),
        },
        "approver2": {
            "email": secret_get("auth.approver2.email"),
            "password": secret_get("auth.approver2.password_hash"),
        },
        "final_approver": {
            "email": secret_get("auth.final_approver.email"),
            "password": secret_get("auth.final_approver.password_hash"),
        },
        "admin": {
            "password": secret_get("auth.admin_password_hash"),
        },
    }


def authenticate_approver(email: str, password: str) -> Optional[str]:
    email = email.strip().lower()
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT role,email,password_hash,active FROM users WHERE active=TRUE"
        ).fetchall()
    for row in rows:
        if hmac.compare_digest(email, row["email"].strip().lower()) and verify_password(password, row["password_hash"]):
            return row["role"]
    return None


def authenticate_admin(password: str) -> bool:
    # Admin credential remains outside the application database by design.
    return verify_password(password, configured_credentials()["admin"]["password"])


def logout(role: str) -> None:
    st.session_state.pop(role, None)
    st.rerun()


# ============================================================
# 5. EMAIL
# ============================================================

def smtp_config() -> dict:
    return {
        "host": secret_get("smtp.host", "smtp.gmail.com"),
        "port": int(secret_get("smtp.port", "465")),
        "username": secret_get("smtp.username"),
        "password": secret_get("smtp.password"),
        "from_name": secret_get("smtp.from_name", APP_NAME),
    }


def send_email(
    to_email: str,
    subject: str,
    body: str,
    attachment_path: Optional[Path] = None,
) -> bool:
    """
    Returns True/False instead of interrupting the application.
    """
    cfg = smtp_config()

    if not cfg["username"] or not cfg["password"]:
        st.warning(tr("email_not_configured"))
        return False

    try:
        msg = EmailMessage()
        msg["From"] = f'{cfg["from_name"]} <{cfg["username"]}>'
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body, subtype="plain", charset="utf-8")

        if attachment_path and attachment_path.exists():
            data = attachment_path.read_bytes()
            msg.add_attachment(
                data,
                maintype="application",
                subtype="pdf",
                filename=attachment_path.name,
            )

        with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=20) as server:
            server.login(cfg["username"], cfg["password"])
            server.send_message(msg)

        return True
    except Exception as exc:
        st.warning(tr("email_failed", error=exc))
        return False


# ============================================================
# 6. PDF GENERATION
# ============================================================

def find_thai_font() -> tuple[Optional[Path], Optional[Path]]:
    candidates = [
        (
            Path("fonts/THSarabun.ttf"),
            Path("fonts/THSarabun-Bold.ttf"),
        ),
        (
            Path("fonts/THSarabunNew.ttf"),
            Path("fonts/THSarabunNew-Bold.ttf"),
        ),
        (
            Path(r"C:\Windows\Fonts\tahoma.ttf"),
            Path(r"C:\Windows\Fonts\tahomabd.ttf"),
        ),
    ]

    for regular, bold in candidates:
        if regular.exists() and bold.exists():
            return regular, bold

    return None, None


def generate_ticket_pdf(
    name: str,
    visit_date: str,
    reason: str,
    areas: str,
    company: str,
    conf_num: str,
) -> Path:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    regular_font, bold_font = find_thai_font()

    if regular_font and bold_font:
        pdf.add_font("FacilityFont", style="", fname=str(regular_font))
        pdf.add_font("FacilityFont", style="B", fname=str(bold_font))
        font_name = "FacilityFont"
    else:
        # Helvetica cannot reliably render Thai. The PDF remains usable for
        # Latin text, while deployment should include TH Sarabun font files.
        font_name = "Helvetica"

    pdf.set_fill_color(19, 43, 78)
    pdf.rect(0, 0, 210, 43, "F")

    pdf.set_y(12)
    pdf.set_font(font_name, "B", 22)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 9, "PLANT ACCESS PASS", ln=True, align="C")

    pdf.set_font(font_name, "", 12)
    pdf.cell(
        0,
        8,
        "Chulabhorn Pharmaceutical Manufacturing Facility",
        ln=True,
        align="C",
    )

    pdf.set_text_color(35, 42, 52)
    pdf.set_y(55)

    def add_row(label: str, value: str) -> None:
        pdf.set_font(font_name, "B", 12)
        pdf.cell(55, 10, label)
        pdf.set_font(font_name, "", 12)
        pdf.multi_cell(0, 10, str(value))
        pdf.set_draw_color(220, 224, 230)
        y = pdf.get_y()
        pdf.line(10, y, 200, y)
        pdf.ln(2)

    add_row("Confirmation", conf_num)
    add_row("Visitor", name)
    add_row("Company", company)
    add_row("Visit date", visit_date)
    add_row("Reason", reason)
    add_row("Zones", areas)

    pdf.ln(12)
    pdf.set_font(font_name, "B", 12)
    pdf.cell(0, 8, "Security instructions", ln=True)
    pdf.set_font(font_name, "", 11)
    pdf.multi_cell(
        0,
        7,
        "Present this pass together with a valid identification document "
        "to facility security. Access is subject to site safety, GMP and "
        "operational requirements.",
    )

    pdf.ln(14)
    pdf.set_font(font_name, "", 9)
    pdf.set_text_color(125, 133, 145)
    pdf.cell(
        0,
        6,
        "Electronically generated confidential document.",
        ln=True,
        align="C",
    )

    filename = GENERATED_DIR / f"Access_Ticket_{conf_num}.pdf"
    pdf.output(str(filename))
    return filename


# ============================================================
# 7. VALIDATION / FILE HANDLING
# ============================================================

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value.strip()))


def save_uploaded_file(uploaded_file, request_id: str) -> str:
    if uploaded_file is None:
        return ""

    extension = Path(uploaded_file.name).suffix.lower()
    if extension not in ALLOWED_UPLOAD_EXTENSIONS:
        raise ValueError("Unsupported file type.")

    file_size = int(getattr(uploaded_file, "size", 0) or 0)
    if file_size > MAX_UPLOAD_MB * 1024 * 1024:
        raise ValueError(f"File exceeds the {MAX_UPLOAD_MB} MB limit.")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = f"{request_id}{extension}"
    destination = UPLOAD_DIR / safe_name

    with destination.open("wb") as output:
        shutil.copyfileobj(uploaded_file, output)

    return str(destination)


# ============================================================
# 8. REQUEST OPERATIONS
# ============================================================

def create_request(
    name: str,
    email: str,
    company: str,
    visit_date: date,
    reason: str,
    areas: list[str],
    health: str,
    document_path: str,
) -> str:
    request_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat(timespec="seconds")

    with db_connection() as conn:
        conn.execute(
            """
            INSERT INTO access_requests (
                id, visitor_name, visitor_email, company, visit_date,
                reason, areas_needed, health_declaration, document_path,
                status, app1_status, app2_status, final_status,
                rejection_reason, timestamp, confirmation_number
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                request_id,
                name.strip(),
                email.strip(),
                company.strip(),
                visit_date.isoformat(),
                reason.strip(),
                ", ".join(areas),
                health,
                document_path,
                "Pending Initial",
                "Pending",
                "Pending",
                "Pending",
                "",
                timestamp,
                "",
            ),
        )

    audit(request_id, email.strip(), "REQUEST_CREATED", f"Zones: {', '.join(areas)}")
    return request_id


def get_request(request_id: str) -> Optional[dict]:
    with db_connection() as conn:
        return conn.execute(
            "SELECT * FROM access_requests WHERE id = %s FOR UPDATE",
            (request_id,),
        ).fetchone()


def list_requests(
    status: Optional[str] = None,
    search: str = "",
    limit: int = 500,
) -> list[dict]:
    sql = "SELECT * FROM access_requests WHERE 1=1"
    params: list = []

    if status and status != "All":
        sql += " AND status = %s"
        params.append(status)

    if search.strip():
        q = f"%{search.strip()}%"
        sql += """
            AND (
                visitor_name LIKE %s
                OR visitor_email LIKE %s
                OR company LIKE %s
                OR confirmation_number LIKE %s
            )
        """
        params.extend([q, q, q, q])

    sql += " ORDER BY timestamp DESC LIMIT %s"
    params.append(limit)

    with db_connection() as conn:
        return conn.execute(sql, params).fetchall()


def approve_request(request_id: str, role: str, actor: str) -> tuple[bool, str]:
    """
    Uses an IMMEDIATE transaction so two simultaneous browser sessions cannot
    accidentally approve the same request in an inconsistent state.
    """
    final_email = get_setting("final_approver")

    with db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM access_requests WHERE id = %s FOR UPDATE",
            (request_id,),
        ).fetchone()

        if not row:
            return False, tr("request_missing")

        if row["status"] == "Rejected" or row["status"] == "Approved":
            return False, tr("already_finalized")

        if role == "approver1":
            if row["app1_status"] != "Pending":
                return False, tr("approval_already")

            conn.execute(
                """
                UPDATE access_requests
                SET app1_status='Approved'
                WHERE id=%s AND app1_status='Pending'
                """,
                (request_id,),
            )

            new_app2 = row["app2_status"]
            if new_app2 == "Approved":
                conn.execute(
                    "UPDATE access_requests SET status='Pending Final' WHERE id=%s",
                    (request_id,),
                )
                should_notify_final = True
            else:
                should_notify_final = False

        elif role == "approver2":
            if row["app2_status"] != "Pending":
                return False, tr("approval_already")

            conn.execute(
                """
                UPDATE access_requests
                SET app2_status='Approved'
                WHERE id=%s AND app2_status='Pending'
                """,
                (request_id,),
            )

            new_app1 = row["app1_status"]
            if new_app1 == "Approved":
                conn.execute(
                    "UPDATE access_requests SET status='Pending Final' WHERE id=%s",
                    (request_id,),
                )
                should_notify_final = True
            else:
                should_notify_final = False

        elif role == "final_approver":
            if row["status"] != "Pending Final":
                return False, tr("not_ready_final")

            if row["final_status"] != "Pending":
                return False, tr("final_already")

            conf = f"AUTH-{secrets.token_hex(4).upper()}"
            conn.execute(
                """
                UPDATE access_requests
                SET status='Approved',
                    final_status='Approved',
                    confirmation_number=%s
                WHERE id=%s AND status='Pending Final'
                """,
                (conf, request_id),
            )
            should_notify_final = False

        else:
            return False, tr("invalid_role")

        conn.execute(
            """
            INSERT INTO audit_log(request_id, actor, action, details, timestamp)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                request_id,
                actor,
                "APPROVED",
                role,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )

    # Notification is deliberately outside the DB transaction.
    if role == "final_approver":
        updated = get_request(request_id)
        if updated:
            pdf_path = generate_ticket_pdf(
                updated["visitor_name"],
                updated["visit_date"],
                updated["reason"],
                updated["areas_needed"],
                updated["company"],
                updated["confirmation_number"],
            )
            send_email(
                updated["visitor_email"],
                "APPROVED: Your Plant Access Ticket",
                (
                    f"Hello {updated['visitor_name']},\n\n"
                    f"Your visit on {updated['visit_date']} has been fully approved.\n\n"
                    "Please find your official access ticket attached. "
                    "Present it to security together with valid ID.\n\n"
                    "Thank you."
                ),
                pdf_path,
            )
            return True, f"{tr('approved')}. {tr('confirmation', id=updated['confirmation_number'])}"

    if should_notify_final and final_email:
        updated = get_request(request_id)
        if updated:
            send_email(
                final_email,
                f"ACTION REQUIRED: Final Approval - {updated['visitor_name']}",
                (
                    "A visitor access request has completed both initial approvals "
                    "and is ready for final review.\n\n"
                    f"Visitor: {updated['visitor_name']}\n"
                    f"Company: {updated['company']}\n"
                    f"Visit date: {updated['visit_date']}\n"
                    f"Reason: {updated['reason']}\n"
                    f"Zones: {updated['areas_needed']}\n"
                ),
            )

    return True, tr("approval_recorded")


def reject_request(
    request_id: str,
    actor: str,
    reason: str,
) -> tuple[bool, str]:
    reason = reason.strip() or (
        "Does not meet current facility safety or operational requirements."
    )

    with db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM access_requests WHERE id=%s FOR UPDATE",
            (request_id,),
        ).fetchone()

        if not row:
            return False, tr("request_missing")

        if row["status"] in ("Approved", "Rejected"):
            return False, tr("already_finalized")

        conn.execute(
            """
            UPDATE access_requests
            SET status='Rejected', rejection_reason=%s
            WHERE id=%s AND status NOT IN ('Approved','Rejected')
            """,
            (reason, request_id),
        )

        conn.execute(
            """
            INSERT INTO audit_log(request_id, actor, action, details, timestamp)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                request_id,
                actor,
                "REJECTED",
                reason,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )

    send_email(
        row["visitor_email"],
        "REJECTED: Plant Access Request",
        (
            f"Hello {row['visitor_name']},\n\n"
            f"Your request to visit on {row['visit_date']} has been rejected.\n\n"
            f"Reason: {reason}\n\n"
            "Please contact your plant liaison if you have questions."
        ),
    )

    return True, tr("rejected_success")


# ============================================================
# 9. DASHBOARD HELPERS
# ============================================================

def pending_for_role(role: str) -> list[dict]:
    if role == "approver1":
        return list_requests("Pending Initial")
    if role == "approver2":
        return list_requests("Pending Initial")
    if role == "final_approver":
        return list_requests("Pending Final")
    return []


def dashboard_counts() -> dict:
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM access_requests GROUP BY status"
        ).fetchall()

    result = {key: 0 for key in STATUS_LABELS}
    for row in rows:
        result[row["status"]] = row["count"]
    return result


def render_request_details(row: dict, show_actions: bool, role: str = ""):
    st.markdown(
        f"""<div class="small-muted">{tr('request_id', id=row['id'])} &nbsp;•&nbsp; {tr('submitted_at', time=row['timestamp'])}</div>""",
        unsafe_allow_html=True,
    )
    c1, c2, c3 = st.columns(3)
    c1.write(f"**{tr('visitor')}**  \n{row['visitor_name']}")
    c2.write(f"**{tr('company_label')}**  \n{row['company']}")
    c3.write(f"**{tr('visit_date_label')}**  \n{row['visit_date']}")
    c1, c2, c3 = st.columns(3)
    c1.write(f"**{tr('email_label')}**  \n{row['visitor_email']}")
    c2.write(f"**{tr('reason_label')}**  \n{row['reason']}")
    c3.write(f"**{tr('zones_label')}**  \n{row['areas_needed']}")
    st.write(f"**{tr('health')}:** {row['health_declaration']}  •  **{tr('status')}:** {status_label(row['status'])}")
    if row["document_path"] and Path(row["document_path"]).exists():
        path=Path(row["document_path"])
        st.download_button(tr("download_doc"), data=path.read_bytes(), file_name=f"Document_{row['visitor_name']}_{row['id'][-6:]}{path.suffix}", key=f"download_{row['id']}")
    else:
        st.caption(tr("no_doc"))
    if not show_actions:
        if row["rejection_reason"]:
            st.error(f"{tr('rejection_reason')}: {row['rejection_reason']}")
        if row["confirmation_number"]:
            st.success(tr("confirmation", id=row['confirmation_number']))
        return
    st.divider()
    reject_reason=st.text_input(tr("rejection_reason"), key=f"rejection_{row['id']}", placeholder=tr("rejection_placeholder"))
    a,b=st.columns(2)
    with a:
        if st.button(tr("approve"), key=f"approve_{row['id']}", use_container_width=True):
            ok,message=approve_request(row["id"], role, actor=st.session_state.get("approver_email","unknown"))
            if ok: st.success(message); time.sleep(.25); st.rerun()
            else: st.error(message)
    with b:
        if st.button(tr("reject"), key=f"reject_{row['id']}", use_container_width=True):
            if not reject_reason.strip(): st.error(tr("enter_rejection"))
            else:
                ok,message=reject_request(row["id"], st.session_state.get("approver_email","unknown"), reject_reason)
                if ok: st.success(message); time.sleep(.25); st.rerun()
                else: st.error(message)


# ============================================================
# 10. VISITOR REGISTRATION
# ============================================================

def visitor_registration_tab() -> None:
    render_hero(tr("visitor_title"), tr("visitor_subtitle"), tr("visitor_kicker"))
    st.info(tr("visitor_info"))
    with st.form("registration_form", clear_on_submit=True):
        st.subheader(tr("visitor_information"))
        c1,c2=st.columns(2)
        with c1:
            name=st.text_input(tr("full_name")); company=st.text_input(tr("company"))
        with c2:
            visitor_email=st.text_input(tr("email")); visit_date=st.date_input(tr("visit_date"), min_value=date.today())
        st.subheader(tr("visit_details"))
        c1,c2=st.columns(2)
        with c1:
            reason_display=st.selectbox(tr("reason"), reason_options())
        with c2:
            zone_display=st.multiselect(tr("zones"), zone_options())
        reason_selection=english_reason(reason_display)
        areas=[english_zone(x) for x in zone_display]
        specified_reason=""
        if reason_selection=="Other":
            specified_reason=st.text_input(tr("other_reason"), placeholder=tr("other_placeholder"))
        st.subheader(tr("documents"))
        uploaded_file=st.file_uploader(tr("upload", mb=MAX_UPLOAD_MB), type=ALLOWED_UPLOAD_TYPES)
        st.subheader(tr("safety"))
        health_check=st.checkbox(tr("safety_text"))
        submitted=st.form_submit_button(tr("submit"), use_container_width=True)
    if not submitted: return
    clean_name=name.strip(); clean_email=visitor_email.strip(); clean_company=company.strip()
    if not clean_name or not clean_email or not clean_company or not areas: st.error(tr("required")); return
    if not valid_email(clean_email): st.error(tr("valid_email")); return
    if reason_selection=="Other" and not specified_reason.strip(): st.error(tr("specify_reason")); return
    if not health_check: st.error(tr("accept_safety")); return
    if visit_date<date.today(): st.error(tr("past_date")); return
    request_id=str(uuid.uuid4()); doc_path=""
    try:
        if uploaded_file: doc_path=save_uploaded_file(uploaded_file, request_id)
        reason=f"Other: {specified_reason.strip()}" if reason_selection=="Other" else reason_selection
        with db_connection() as conn:
            conn.execute("""INSERT INTO access_requests (id,visitor_name,visitor_email,company,visit_date,reason,areas_needed,health_declaration,document_path,status,app1_status,app2_status,final_status,rejection_reason,timestamp,confirmation_number) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(request_id,clean_name,clean_email,clean_company,visit_date.isoformat(),reason,", ".join(areas),"Accepted",doc_path,"Pending Initial","Pending","Pending","Pending","",datetime.now().isoformat(timespec="seconds"),""))
        audit(request_id,clean_email,"REQUEST_CREATED",f"Zones: {', '.join(areas)}")
        body=("ACTION REQUIRED: New Plant Access Request\n\n" f"Visitor: {clean_name}\n" f"Company: {clean_company}\n" f"Email: {clean_email}\n" f"Requested date: {visit_date.isoformat()}\n" f"Reason: {reason}\n" f"Zones: {', '.join(areas)}\n" f"Supporting document: {'Yes' if doc_path else 'No'}\n\n" "Please open the Plant Access Management system and review the request.")
        email_results=[]
        for recipient in (get_setting("approver1"),get_setting("approver2")):
            if recipient: email_results.append(send_email(recipient,f"APPROVAL REQUIRED: Access Request - {clean_name}",body))
        st.success(tr("submitted")); st.code(request_id,language="text")
        if email_results and not all(email_results): st.warning(tr("stored_email_warning"))
    except Exception as exc:
        if doc_path:
            try: Path(doc_path).unlink(missing_ok=True)
            except Exception: pass
        st.error(tr("unable_submit", error=exc))


# ============================================================
# 11. APPROVER DASHBOARD
# ============================================================

def approver_dashboard_tab() -> None:
    render_hero(tr("approval_title"), tr("approval_subtitle"), tr("approval_kicker"))
    session_role=st.session_state.get("approver_role")
    if not session_role:
        with st.form("approver_login"):
            st.subheader(tr("secure_signin")); email=st.text_input(tr("registered_email")); password=st.text_input(tr("password"),type="password"); submitted=st.form_submit_button(tr("signin"),use_container_width=True)
        if submitted:
            if not email.strip() or not password: st.error(tr("enter_credentials")); return
            role=authenticate_approver(email,password)
            if role: st.session_state["approver_role"]=role; st.session_state["approver_email"]=email.strip().lower(); st.rerun()
            else: st.error(tr("invalid_credentials"))
        return
    role=session_role; email=st.session_state.get("approver_email",""); label=role_label(role)
    top1,top2=st.columns([8,1]); top1.success(tr("signed_in",label=label,email=email))
    if top2.button(tr("signout"),key="approver_logout",use_container_width=True): logout("approver_role")
    counts=dashboard_counts(); c1,c2,c3,c4=st.columns(4); c1.metric(tr("awaiting_initial"),counts["Pending Initial"]); c2.metric(tr("awaiting_final"),counts["Pending Final"]); c3.metric(tr("approved"),counts["Approved"]); c4.metric(tr("rejected"),counts["Rejected"])
    pending_tab, approved_tab=st.tabs([tr("pending"),tr("approved_visitors")])
    with pending_tab:
        search=st.text_input(tr("search_pending"),placeholder=tr("search_placeholder"),key="pending_search")
        if role=="approver1": rows=[r for r in list_requests("Pending Initial",search) if r["app1_status"]=="Pending"]
        elif role=="approver2": rows=[r for r in list_requests("Pending Initial",search) if r["app2_status"]=="Pending"]
        else: rows=list_requests("Pending Final",search)
        if not rows: st.info(tr("no_pending"))
        for row in rows:
            title=f"{row['visitor_name']}  •  {row['company']}  •  {row['visit_date']}"
            with st.expander(title,expanded=True): render_request_details(row,show_actions=True,role=role)
    with approved_tab:
        st.caption(tr("approved_subtitle"))
        approved_search=st.text_input(tr("search_approved"),placeholder=tr("approved_placeholder"),key="approved_search")
        approved_rows=list_requests("Approved",approved_search,limit=1000)
        if not approved_rows:
            st.info(tr("no_approved"))
        else:
            for row in approved_rows:
                with st.container(border=True):
                    a,b,c=st.columns([2.3,2.2,2.0])
                    a.markdown(f"### {row['visitor_name']}")
                    a.write(f"**{tr('company_label')}:** {row['company']}")
                    b.markdown(f"**{tr('arrival_confirm')}**")
                    b.code(row['confirmation_number'] or '—')
                    b.write(f"**{tr('visit_date_label')}:** {row['visit_date']}")
                    c.write(f"**{tr('visitor_email')}:** {row['visitor_email']}")
                    c.write(f"**{tr('zones_requested')}:** {row['areas_needed']}")
                    st.caption(tr("arrival_note"))
                    if row["document_path"] and Path(row["document_path"]).exists():
                        path=Path(row["document_path"])
                        st.download_button(tr("view_pass"),data=path.read_bytes(),file_name=f"Document_{row['visitor_name']}_{row['id'][-6:]}{path.suffix}",key=f"approved_doc_{row['id']}")


# ============================================================
# 12. ADMIN DASHBOARD
# ============================================================

def admin_dashboard_tab() -> None:
    render_hero(tr("admin_title"),tr("admin_subtitle"),tr("admin_kicker"))
    if not st.session_state.get("admin_logged_in",False):
        with st.form("admin_login"):
            password=st.text_input(tr("admin_password"),type="password"); submitted=st.form_submit_button(tr("admin_signin"),use_container_width=True)
        if submitted:
            if authenticate_admin(password): st.session_state["admin_logged_in"]=True; st.rerun()
            else: st.error(tr("invalid_admin"))
        return
    c1,c2=st.columns([8,1]); c1.success(tr("admin_active"))
    if c2.button(tr("signout"),key="admin_logout",use_container_width=True): st.session_state["admin_logged_in"]=False; st.rerun()
    st.subheader(tr("accounts_routing")); st.caption(tr("single_source"))
    for user in get_users():
        role=user["role"]; label=role_label(role)
        with st.container(border=True):
            cols=st.columns([1.5,3,1.5,1.5]); cols[0].markdown(f"**{label}**")
            new_email=cols[1].text_input(tr("email_field"),value=user["email"],key=f"email_{role}")
            new_password=cols[2].text_input(tr("new_password"),type="password",key=f"pw_{role}",placeholder=tr("leave_blank"))
            active=cols[3].checkbox(tr("active"),value=bool(user["active"]),key=f"active_{role}")
            if st.button(tr("save_account"),key=f"save_{role}",use_container_width=True):
                try:
                    update_user(role,new_email,new_password or None,active); audit(None,"admin","USER_UPDATED",f"{role}: {new_email}"); st.success(tr("updated",label=label)); st.rerun()
                except Exception as exc: st.error(str(exc))
    st.divider(); st.subheader(tr("smtp")); st.info(tr("smtp_info")); cfg=smtp_config(); st.write(f"**{tr('server')}:** {cfg['host']}:{cfg['port']}"); st.write(f"**{tr('sender')}:** {cfg['username'] or tr('not_configured')}")
    test_recipient=st.text_input(tr("test_email_to"),value=cfg["username"] or "")
    if st.button(tr("send_test"),use_container_width=True):
        if not valid_email(test_recipient): st.error(tr("enter_valid_recipient"))
        else:
            ok=send_email(test_recipient,"Plant Access System - SMTP Test","This is a test email from the Plant Access Management System.")
            if ok: audit(None,"admin","SMTP_TEST",test_recipient); st.success(tr("test_success"))
    st.divider(); st.subheader(tr("monitoring")); counts=dashboard_counts(); c1,c2,c3,c4=st.columns(4); c1.metric(tr("awaiting_initial"),counts["Pending Initial"]); c2.metric(tr("awaiting_final"),counts["Pending Final"]); c3.metric(tr("approved"),counts["Approved"]); c4.metric(tr("rejected"),counts["Rejected"])
    c1,c2=st.columns(2)
    with c1: status_display=st.selectbox(tr("status_filter"),[tr("all")]+[status_label(x) for x in STATUS_LABELS.keys()])
    with c2: search=st.text_input(tr("search"),placeholder=tr("search_monitor_placeholder"))
    reverse_status={status_label(x):x for x in STATUS_LABELS.keys()}; status_filter=reverse_status.get(status_display,"All")
    rows=list_requests(status_filter,search,limit=1000)
    if rows:
        display=pd.DataFrame([{tr("visitor"):r["visitor_name"],tr("company_label"):r["company"],tr("visit_date_label"):r["visit_date"],tr("status"):status_label(r["status"]),tr("initial_1"):status_label(r["app1_status"]),tr("initial_2"):status_label(r["app2_status"]),tr("final_approver"):status_label(r["final_status"]),tr("arrival_confirm"):r["confirmation_number"],tr("submitted_at", time=""):r["timestamp"]} for r in rows])
        st.dataframe(display,hide_index=True,use_container_width=True)
    else: st.info(tr("no_matching"))
    st.divider(); st.subheader(tr("audit"))
    with db_connection() as conn:
        audit_rows = conn.execute("SELECT timestamp, actor, action, request_id, details FROM audit_log ORDER BY id DESC LIMIT 500").fetchall()
    audit_df = pd.DataFrame(audit_rows)
    audit_df = audit_df.rename(columns={
        "timestamp": tr("submitted_at", time="").rstrip(": "),
        "actor": tr("visitor") + " / Actor",
        "action": tr("status") + " / Action",
        "request_id": tr("request_id", id="").rstrip(": "),
        "details": tr("reason_label"),
    })
    st.dataframe(audit_df,hide_index=True,use_container_width=True)


# ============================================================
# 13. MAIN
# ============================================================

def main() -> None:
    apply_liquid_glass_ui()

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)

    try:
        init_db()
    except Exception as exc:
        st.error(tr("database_error"))
        st.exception(exc)
        st.stop()

    st.markdown(
        f"""
        <div style="
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:8px;
        ">
            <div>
                <div style="
                    font-weight:750;
                    font-size:1.05rem;
                    color:#fff;
                ">
                    🏭 {APP_NAME}
                </div>
                <div class="small-muted">
                    {tr("app_subtitle")}
                </div>
            </div>
            <div class="status-pill">{tr("secure")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    lang_col, theme_col, _ = st.columns([1.3, 1.3, 3.4])
    with lang_col:
        selected_language = st.selectbox(tr("language"), ["English", "ไทย"], index=0 if current_language()=="English" else 1, key="language_selector")
        if selected_language != current_language():
            st.session_state["language"] = selected_language
            st.rerun()
    with theme_col:
        theme_choice = st.selectbox(tr("theme"), [tr("dark"), tr("light")], index=0 if st.session_state.get("theme","dark")=="dark" else 1, key="theme_selector")
        new_theme = "dark" if theme_choice == tr("dark") else "light"
        if new_theme != st.session_state.get("theme","dark"):
            st.session_state["theme"] = new_theme
            st.rerun()

    tab1, tab2, tab3 = st.tabs(
        [tr("visitor_tab"), tr("approval_tab"), tr("admin_tab")]
    )

    with tab1:
        visitor_registration_tab()

    with tab2:
        approver_dashboard_tab()

    with tab3:
        admin_dashboard_tab()


if __name__ == "__main__":
    main()

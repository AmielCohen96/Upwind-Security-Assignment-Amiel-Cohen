# Upwind Security Home Assignment

**Candidate:** Amiel Cohen  

This repository contains the complete submission for the Upwind Security home assignment. The project is divided into two distinct parts, addressing both client-side threat detection and secure backend architecture.


## Repository Structure

### 📁 [Part 1: Gmail Security Add-on](./Part1-Gmail-Security-Addon)
A contextual Gmail sidebar add-on built with Google Apps Script. It acts as a real-time threat detection engine, analyzing incoming emails and assigning a maliciousness score based on a **Confidence-Tiered Architecture**. It combines structural header analysis (e.g., SPF/DKIM, Message-ID), zero-day heuristic checks (Typosquatting, Homoglyphs), and reputation checks (Google Safe Browsing API).
* 👉 [Read the full Part 1 Documentation & Code Review](./Part1-Gmail-Security-Addon/README.md)

### 📁 [Part 2: Security Operations Portal](./Part2-Security-Operations-Portal)
A full-stack, secure-by-design backend architecture for a Security Operations Center (SOC) portal. It features strict Role-Based Access Control (RBAC), JWT authentication via HttpOnly cookies, database security, and a defense-in-depth approach to API endpoint protection.
* 👉 [Read the full Part 2 Documentation](./Part2-Security-Operations-Portal/README.md) 

---
*Developed for the Upwind Security R&D evaluation process.*
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-10-05

### Added

- **Phase 1 Complete: Data Models and Foundation**
  - Created `Scanner` model with support for Network Range and Cisco Switch scan types
  - Created `ScanRun` model to track scan execution history and metrics
  - Created `DiscoveredDevice` model to audit device discovery operations
  - Created `DiscoveredIPAddress` model to audit IP address discovery operations
  - Implemented choice sets for scanner types, statuses, protocols, and run states
  - Built complete CRUD views for all models using NetBox generic views
  - Added Django Tables2 tables with proper column configuration
  - Created filtersets for list view filtering
  - Implemented forms with dynamic field visibility based on scanner type
  - Added comprehensive navigation menu with grouped items
  - Created detail templates for Scanner and ScanRun views
  - Updated plugin metadata with proper author information
  - Added dependencies: python-nmap, netmiko, pysnmp

### Documentation

- Comprehensive README with installation, usage, and architecture sections
- Migration guide for database setup
- Copilot instructions with phased implementation strategy
- Task-specific requirements and deliverables documented

### Next Steps

- **Phase 2**: Implement background jobs for network range and Cisco switch scanning
- **Phase 3**: Add "Run Scan" button and scan execution UI
- **Phase 4**: REST API endpoints for scanners and scan runs
- **Phase 5**: Search integration and GraphQL support
- **Phase 6**: Docker integration examples with virtual switch testing
- **Phase 7**: Screenshots, architecture documentation, and final polish

## [Unreleased]

### Planned

- Network range scan job implementation with python-nmap
- Cisco switch scan job implementation with netmiko/pysnmp
- Scan execution action view and button
- Credential encryption enhancements
- Automatic scan scheduling
- Email notifications for scan completion/failure
- Advanced filtering and reporting
- Export functionality for scan results

## 0.1.0 (2025-10-04)

* First release on PyPI.

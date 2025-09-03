# SecureScan Pro - Security Scanning Platform

## Overview

SecureScan Pro is a comprehensive security scanning platform that integrates multiple security testing tools for automated vulnerability assessment. The application provides a web-based interface for initiating, monitoring, and reporting on various types of security scans including subdomain enumeration, XSS detection, SQL injection testing, network scanning, and OSINT gathering.

The platform follows a full-stack architecture with a React frontend for user interaction and an Express.js backend that orchestrates Python-based security tools. Real-time updates are delivered through WebSocket connections, providing live feedback on scan progress and results.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
The client-side application is built with React and TypeScript, utilizing modern tooling including:
- **Vite** for build tooling and development server with hot module replacement
- **Tailwind CSS** with shadcn/ui components for consistent, dark-themed styling
- **React Router (Wouter)** for client-side routing
- **TanStack Query** for server state management and caching
- **React Hook Form** with Zod validation for form handling

The frontend implements a dashboard-centric design with real-time status updates, scan management interfaces, and detailed reporting capabilities.

### Backend Architecture
The server-side follows an Express.js-based REST API architecture with:
- **TypeScript** for type safety across the application
- **Express.js** middleware for request processing, logging, and error handling
- **WebSocket server** for real-time communication with clients
- **Modular service layer** separating business logic (scan orchestration, tool management)
- **Python tool integration** through subprocess execution with timeout controls

The backend manages scan lifecycle states, coordinates multiple security tools, and provides progress tracking through WebSocket broadcasts.

### Data Storage Solutions
The application uses a hybrid storage approach:
- **PostgreSQL database** with Drizzle ORM for persistent data storage
- **In-memory storage** fallback for development and testing environments
- **Database schemas** for users, scans, vulnerabilities, and tool status tracking
- **JSONB fields** for storing flexible scan results and configuration data

### Authentication and Authorization
Currently implements a basic session-based authentication system with:
- User account management through PostgreSQL storage
- Session handling via connect-pg-simple middleware
- Placeholder authentication structure ready for enhancement

### Tool Integration Architecture
Security tools are integrated through a Python-based execution framework:
- **Subprocess management** with configurable timeouts and error handling
- **Standardized tool output** parsing to common vulnerability schema
- **Tool status monitoring** with success rate tracking and health checks
- **Concurrent execution** support for parallel scan operations

The system supports multiple tool categories:
- Subdomain enumeration (Sublist3r, Subfinder, Sudomy, Dome)
- XSS detection (XSStrike, Dalfox, XSS-Checker, xssFuzz)
- SQL injection testing (SQLMap, Ghauri, GraphQLmap, SQLiDetector)
- Network scanning (Nmap, Masscan, Metasploit integration)
- OSINT gathering (DNS, WHOIS, certificate analysis)

### Real-time Communication
WebSocket implementation provides:
- Live scan progress updates with percentage completion
- Real-time vulnerability discovery notifications
- Tool status changes and health monitoring
- Terminal-style output streaming for scan logs

## External Dependencies

### Database Services
- **PostgreSQL** as the primary database with Neon serverless hosting support
- **Drizzle ORM** for database schema management and migrations
- **connect-pg-simple** for PostgreSQL-backed session storage

### UI Framework and Styling
- **Radix UI** component primitives for accessible, unstyled components
- **Tailwind CSS** for utility-first styling with custom cyber-security theme
- **Lucide React** for consistent iconography
- **shadcn/ui** component system for pre-built, customizable components

### Security Tool Dependencies
Python-based tools requiring specific packages:
- **DNS resolution** libraries (dnspython, python-whois)
- **HTTP clients** (requests, urllib3) for web application testing
- **SSL/TLS analysis** (pyOpenSSL, cryptography)
- **Web scraping** (beautifulsoup4, lxml, selenium)
- **Network scanning** (python-nmap, masscan integration)

### Development and Build Tools
- **Vite** with React plugin for fast development and optimized production builds
- **esbuild** for server-side bundling and performance optimization
- **TypeScript** for compile-time type checking across frontend and backend
- **Replit integration** plugins for development environment compatibility

### External APIs and Services
The platform is designed to integrate with:
- **Shodan API** for internet-wide device scanning
- **CVE databases** for vulnerability correlation
- **Certificate transparency logs** for subdomain discovery
- **DNS resolvers** for domain intelligence gathering

The architecture supports horizontal scaling through service separation and can accommodate additional security tool integrations through the standardized Python tool execution framework.
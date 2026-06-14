# Contributing Guide

Thank you for contributing to Snypshark.

This document defines the official development workflow.

---

# Development Model

Snypshark follows:

Milestone → Epic → Issue → Pull Request

GitHub Projects is the operational source of truth.

---

# Branch Strategy

## Main

Production-ready code.

Protected branch.

Direct pushes are forbidden.

---

## Develop

Integration branch.

All Pull Requests target develop.

---

## Branch Naming

feature/<name>

fix/<name>

refactor/<name>

docs/<name>

security/<name>

research/<name>

---

# Commit Convention

Snypshark uses Conventional Commits.

Examples:

feat(core): implement TelemetrySource

feat(capture): add LiveCaptureSource

fix(cli): correct argument validation

refactor(core): migrate to TelemetryEngine

docs(handbook): update roadmap

test(core): add TelemetryEvent fixtures

security(cli): sanitize user input

---

# Pull Requests

Requirements:

* Linked Issue
* Updated tests
* Updated documentation
* Passing CI

PRs without Issues are rejected.

---

# Issue Classification

Every issue must include:

* Type
* Priority
* Component
* Milestone
* Epic

---

# Security Reporting

Security vulnerabilities must never be opened as public bug reports.

Use private disclosure channels.

Severity:

P0 Critical

P1 High

P2 Medium

P3 Low

---

# Testing Requirements

New functionality requires:

* Unit Tests
* Integration Tests
* Regression Tests (when applicable)

No feature is considered complete without test coverage.

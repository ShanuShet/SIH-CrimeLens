# CrimeLens

**CrimeLens** is a secure, case-centric investigation intelligence
platform designed to turn fragmented investigative evidence into
structured, traceable, and actionable intelligence.

It brings evidence ingestion, entity resolution, relationship analysis,
risk intelligence, evidence integrity, and a grounded investigation
assistant into one investigation workflow.

> **Core workflow:**\
> **Evidence Ingestion → Entity Resolution → Graph Fusion → Risk
> Intelligence → Grounded AI Assistant**

------------------------------------------------------------------------

## Overview

Real-world investigations often involve disconnected artifacts such as
FIRs, surveillance reports, call-detail records, financial transaction
logs, criminal records, spreadsheets, JSON files, and witness
statements.

CrimeLens connects these artifacts to a specific investigation case and
provides investigators with:

-   A centralized evidence repository
-   Structured and unstructured evidence ingestion
-   Entity extraction and resolution
-   Case-scoped relationships
-   Interactive investigation graphs
-   Deterministic and explainable risk scoring
-   Evidence provenance and integrity verification
-   Case-grounded investigation assistance
-   A secure, isolated investigation context

The platform is designed around **traceability and evidence grounding**,
so analytical outputs can be connected back to the underlying case
evidence.

------------------------------------------------------------------------

## Key Capabilities

### 1. Evidence Ingestion

CrimeLens supports investigative artifacts such as:

-   FIR / police reports
-   Surveillance reports
-   Witness statements
-   Criminal records
-   Call-detail records
-   Financial transaction logs
-   Entity master spreadsheets
-   JSON evidence

Uploaded artifacts are stored in the case evidence repository and can be
inspected, verified, viewed, and downloaded.

The evidence workflow also records integrity information using **SHA-256
hashing**.

### 2. Entity Intelligence

CrimeLens extracts and organizes investigative entities such as:

-   People
-   Phone numbers
-   Bank accounts
-   Vehicles
-   Locations

The platform supports entity resolution so that related references can
be connected while preserving distinct entities when they should not be
merged.

### 3. Relationship Intelligence

Investigative relationships are represented explicitly, including
relationships such as:

-   `PART_OF_CASE`
-   `CALL_MADE_TO`
-   Financial transfer relationships
-   Other case-derived connections

Relationships can include timestamps and transaction amounts/volumes
where available.

### 4. Investigation Graph

The investigation graph provides a force-directed visual representation
of:

-   People
-   Phones
-   Bank accounts
-   Vehicles
-   Locations
-   Case membership
-   Communication links
-   Financial relationships

Investigators can:

-   Search graph nodes and edges
-   Filter relationships
-   Filter risk levels
-   Zoom and fit the graph
-   Display entity and edge labels
-   Select entities for forensic details

This allows investigators to move from individual evidence records to a
connected investigation view.

### 5. Risk Intelligence

CrimeLens provides deterministic, bounded **0--100 risk scoring** for
cases and entities.

The Risk Analysis view provides:

-   Overall case risk
-   Entity risk scores
-   Risk levels
-   Contributing factors
-   Relationship counts
-   Entity inspection

The scoring is intended to be explainable rather than a black-box
classification.

### 6. Grounded Investigation Assistant

The Investigation Assistant allows investigators to ask evidence-related
questions about the active case.

Example investigation actions include:

-   Summarize case evidence
-   Identify high-risk links
-   Analyze financial transfers
-   Analyze communication links
-   Identify evidence gaps

Responses can incorporate:

-   Case evidence
-   Resolved entities
-   Graph relationships
-   Evidence provenance

The assistant is designed to remain grounded in the active investigation
context rather than mixing information from unrelated cases.

### 7. Evidence Provenance & Integrity

CrimeLens maintains a traceable relationship between analytical results
and their source evidence.

The evidence interface exposes integrity and indexing state, including:

-   File identity
-   Classification
-   Case association
-   File size
-   Integrity verification
-   RAG indexing status
-   Evidence actions

Evidence artifacts are protected with SHA-256 integrity records so that
investigators can verify whether stored evidence remains unchanged.

### 8. Case Isolation

CrimeLens uses an active investigation case context throughout the
platform.

The interface clearly identifies the active case and provides case
switching controls.

Case-scoped data includes:

-   Evidence
-   Relationships
-   Graph analysis
-   Risk analysis
-   Investigation assistant context

This helps prevent information from one investigation from
unintentionally appearing in another investigation.

------------------------------------------------------------------------

## Investigation Pipeline

``` text
                    ┌─────────────────────┐
                    │   Evidence Sources  │
                    │ FIR / CDR / Finance │
                    │ Reports / JSON / XLS │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Evidence Ingestion │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Entity Resolution   │
                    │ People / Phones /   │
                    │ Accounts / Vehicles │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Graph Fusion      │
                    │ Relationships +     │
                    │ Case Context        │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
       ┌──────────────────┐        ┌──────────────────┐
       │ Risk Intelligence│        │ Evidence         │
       │ 0–100 Scoring    │        │ Integrity        │
       └────────┬─────────┘        └────────┬─────────┘
                │                           │
                └─────────────┬─────────────┘
                              ▼
                    ┌─────────────────────┐
                    │ Grounded            │
                    │ Investigation       │
                    │ Assistant           │
                    └─────────────────────┘
```

------------------------------------------------------------------------

## Application Modules

  -----------------------------------------------------------------------
  Module                              Purpose
  ----------------------------------- -----------------------------------
  **Command Center**                  Central investigation workspace

  **Cases**                           Create and manage investigation
                                      contexts

  **Evidence Locker**                 Store, inspect, verify, and trace
                                      evidence

  **Entity Master**                   Review resolved investigative
                                      entities

  **Relationships**                   Inspect structured case
                                      relationships

  **Investigation Graph**             Visualize connected investigative
                                      intelligence

  **Risk Analysis**                   Review case and entity risk
                                      intelligence

  **Investigation Assistant**         Ask grounded questions about the
                                      active case

  **Security & Integrity**            Support evidence verification and
                                      secure investigation workflows
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## Security Principles

CrimeLens is designed around several security principles:

### Case isolation

Investigation data is scoped to the active case wherever case-specific
analysis is performed.

### Evidence integrity

Evidence artifacts are associated with SHA-256 integrity information for
verification.

### Role-based access

The platform supports role-aware access for investigation workflows,
including:

-   Administrator
-   Investigator
-   Auditor

### Protected evidence workflow

Evidence is handled through the application rather than relying on
unrestricted public file access.

### Auditability

Important investigation and security operations can be recorded for
traceability.

### Grounded intelligence

The investigation assistant is designed to use the active case's
evidence and relationships as its analytical context.

------------------------------------------------------------------------

## Technology

The project is implemented as a Python web application with a
browser-based investigation interface.

Core technologies/components include:

-   **Python**
-   **FastAPI**
-   **SQLAlchemy**
-   **SQLite**
-   **HTML / CSS / JavaScript**
-   **RAG-based evidence retrieval**
-   **LLM integration**
-   **Network/graph visualization**
-   **SHA-256 evidence hashing**

------------------------------------------------------------------------

## Project Structure

``` text
SIH-CrimeLens/
│
├── app/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   ├── rbac.py
│   │
│   ├── services/
│   │   ├── assistant.py
│   │   ├── graph_service.py
│   │   ├── ingestion.py
│   │   ├── risk_service.py
│   │   ├── llm_provider.py
│   │   └── rag_service.py
│   │
│   ├── static/
│   │   ├── app.js
│   │   └── styles.css
│   │
│   └── templates/
│       ├── index.html
│       └── home.html
│
├── tests/
│   ├── test_live_server.py
│   ├── test_redesign_and_stats.py
│   ├── test_suite.py
│   ├── test_supervisor_audit.py
│   └── test_ui_integrity.py
│
├── .gitignore
└── README.md
```

------------------------------------------------------------------------

## Local Setup

### 1. Clone the repository

``` bash
git clone https://github.com/ShanuShet/SIH-CrimeLens.git
cd SIH-CrimeLens
```

### 2. Create a virtual environment

Windows:

``` powershell
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

Install the project's Python dependencies using the dependency file
included in the repository, if present.

For a fresh environment, make sure the required application and
document-processing dependencies are installed.

### 4. Configure environment variables

Create a local `.env` file for environment-specific configuration and
secrets.

Do **not** commit `.env` or API keys to Git.

### 5. Start the application

For the FastAPI application, run:

``` bash
uvicorn app.main:app --reload
```

Then open the local application in a browser.

------------------------------------------------------------------------

## Testing

The repository contains automated tests covering areas such as:

-   Application/server behavior
-   Statistics and redesign behavior
-   Core CrimeLens functionality
-   Supervisor/audit requirements
-   UI integrity

Run the test suite with:

``` bash
pytest
```

------------------------------------------------------------------------

## Evidence-to-Intelligence Example

A typical investigation can follow this sequence:

``` text
Upload CDR
     │
     ▼
Extract phone entities
     │
     ▼
Resolve entities
     │
     ▼
Create CALL_MADE_TO relationships
     │
     ▼
Attach relationships to active case
     │
     ▼
Visualize communication network
     │
     ▼
Calculate risk signals
     │
     ▼
Ask the Investigation Assistant
     │
     ▼
Trace the response back to evidence
```

The same workflow can incorporate financial transaction data, account
entities, vehicles, people, locations, and other investigative
artifacts.

------------------------------------------------------------------------

## Design Goals

CrimeLens is built around five primary goals:

1.  **Connect fragmented evidence**
2.  **Preserve investigative context**
3.  **Make relationships visible**
4.  **Keep analytical outputs explainable and traceable**
5.  **Keep AI assistance grounded in case evidence**

------------------------------------------------------------------------

## Important Notes

CrimeLens is an investigative intelligence and evidence-analysis
platform. Risk scores, graph relationships, entity resolution, and
AI-generated summaries are analytical aids and should be reviewed by
authorized investigators against the underlying evidence.

The platform does not replace investigative judgment or formal legal
processes.

------------------------------------------------------------------------

## Demo

The project demonstration showcases the complete workflow:

**Command Center → Evidence Locker → Entity Intelligence → Relationships
→ Investigation Graph → Risk Analysis → Investigation Assistant**

The demonstration also shows active-case isolation, evidence integrity
status, graph relationships, risk scoring, and evidence-grounded
assistant responses.

------------------------------------------------------------------------

## License

Add the project's intended license here before public distribution.

------------------------------------------------------------------------

## Project

**CrimeLens --- Investigation Intelligence**

> From fragmented evidence to actionable intelligence.

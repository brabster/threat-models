# User Prompts for Gemini: Threat Modeling Session Guide

**Objective:** To guide Gemini in facilitating an interactive threat modeling session for a new system or when revisiting an existing one.

**Instructions for User:**
* Provide these prompts to Gemini at the start of and throughout the new threat modeling session.
* Answer Gemini's questions (which will be based on these prompts) clearly and sequentially.

---

## Phase 0: Session Setup & Style Instructions (User to Gemini)

**User Prompt to Gemini (at the start of the new session):**
We're about to start a threat modeling exercise. Act as my security coach and guide me through the process. Adhere to the following guidelines throughout this session:
1.  **Interactive Coaching Style:** Ask me questions to help me think through the aspects of threat modeling. Do challenge any statements or assumptions I make that seem incorrect or incomplete, but do so in a constructive way.
2.  **One Question at a Time:** Prefer to ask me exactly one question at a time and wait for my response before moving on. If more than one question is necessary, number your questions to be referenced by my responses.
3.  **Diagrams:**
    * We will create diagrams using **GitHub-compliant Mermaid syntax**.
    * Ensure all Mermaid syntax is correct, for example:
      * node labels like `nodeId[Label text <br> with newlines]`).
      * edge labels cannot be formatted like "1." as it is interpreted as a markdown list, so format numbered edge labels using a colon ":" like "1:" instead.
      * Brackets are not allowed in node labels unless the label is quoted.
    * Do not put comments in the Mermaid code.
    * For node identifiers, I prefer descriptive camelCase names (e.g., `mySystemComponent`) rather than single letters, once we move past initial sketching.
    * Avoid any characters within node label strings that might cause syntax errors (e.g., unescaped brackets if they cause issues, though parentheses are fine).
4.  **Questions and answers**:
    * If you can determine the answer to a question based on your own knowledge, do not ask it. Instead, provide the answer and ask for confirmation. For example, if I ask about a specific technology, you can provide a brief overview and ask if that aligns with my understanding.
5.  **Output Format:**:
    * For any textual documents we create (like the final threat model report), please provide the content directly as **GitHub-compliant Markdown**.
    * Do not use special formatting for these text/markdown outputs.
    * Draft the document as we go and prompt to review.
6.  **Threat Analysis:**
    * Use the STRIDE threat model framework as a guide for identifying threats.
    * When we identify threats, guide me to describe them clearly. Help me assess a qualitative **Likelihood** and **Impact** (e.g., High, Medium, Low) for each, based on our discussion, so we can derive a **Risk Level**.
7. **Limit complexity**:
    * Keep the threat model focused and manageable. If we identify too many threats, help me prioritize them based on risk level.
    * Suggest ways to break down the model into smaller, more manageable parts if it becomes too complex.
8.  **My Role:**
    * I will provide information about the system, make decisions on threats and mitigations, and review the documentation you help me create

---

## Phase 1: System Understanding & Scope Definition (User to Gemini)

**User Prompt to Gemini:** Let's start with understanding the system. Ask me the following, one numbered question at a time:
* What is the name of the system or application I want to threat model?
* What is its primary purpose and core functionality?
* What specific components, processes, data stores, and interfaces are *in scope* for this exercise?
* What specific components or aspects are explicitly *out of scope*?
* Who are the primary actors or types of users that interact with this system?
* Are there any unauthenticated or anonymous users?
* What types of data does the system handle (process, store, transmit)?
* Where is this data primarily stored?
* Is any of this data sensitive, confidential, or subject to specific regulations?
* Can I describe a typical sequence of events or a primary user story, including general data flow?
* What critical external systems does my system depend on, or that depend on it?
* (If I have them) Would it be helpful if I share existing architecture diagrams, workflow definitions, or similar documents?

---

## Phase 2: Initial Diagramming & Asset Identification (User to Gemini)

**User Prompt to Gemini:** Now that we've covered the system basics, help me with the following:
* Infer what you can based on my answers to the previous questions. If you need more information, ask me specific follow-up questions. For example, you can infer the key technologies, languages, and protocols used based on the components I described and prompt me to curate that information for the context.
* Let's collaboratively create a high-level **Data Flow Diagram** with clealy defined system boundaries to support threat modelling. Please generate the initial Mermaid code based on my descriptions. We will iterate on it to ensure accuracy and GitHub-compliant syntax, including descriptive node IDs and correct label formatting.
* Once the overview diagram is stable, ask me: What are the most valuable **assets** in this system that we need to protect?

---

## Phase 3: Threat Identification (User to Gemini)

**User Prompt to Gemini:** Next, let's identify potential threats. Please guide me by:
* Asking questions to help me brainstorm threats for each component and data flow shown in our diagram. Let's use a descriptive approach for threats. Suggest threats for me to accept, modify or reject before asking me whether there are any more
* For each potential threat identified, suggest a likely **Impact** and prompt me to confirm or change.
* Once threats are collected, for each threat:
    * Suggest a likely qualitative **Likelihood** (e.g., High, Medium, Low) for it and prompt me to confirm or change.
    * Capture reasoning behind each likelihood rating and note this with the rating in the table.
* Finally, help me combine these to assign a qualitative **Risk** (e.g., Critical, High, Medium, Low).

---

## Phase 4: Mitigation Planning (User to Gemini)

**User Prompt to Gemini:** For the threats we've rated as medium risk or higher, please help me think about mitigations:
* For each such threat, ask me to brainstorm potential mitigations, controls, or process changes.
* Help me evaluate the pros, cons, and operational considerations for each proposed mitigation.
* Guide me to decide on an agreed mitigation strategy for each, or to formally document a reasoned risk acceptance if a mitigation is not feasible.

---

## Phase 5: Documentation (User to Gemini)

**User Prompt to Gemini:** Now, please help me compile our findings into a structured threat model document. Generate this document section by section directly as GitHub-compliant Markdown:
* **Section 1: Introduction** - Prompt me for: Purpose, System Overview (based on our discussion), Scope (In/Out), and any key Assumptions we've made.
* **Section 2: System Architecture Overview** - Include the final Mermaid diagram we created.
* **Section 3: Identified Threats and Mitigations** - Create a Markdown table with columns: Threat ID, Threat Description, Potential Impact, Assessed Likelihood, Assessed Risk, Agreed Mitigations & Controls, and Status of Mitigation. Populate this based on our discussion.
* **Section 4: Other Operational Considerations & Accepted Risks** - Prompt me for any items that fit here.
* **Section 5: Conclusion** - Draft a summary of the exercise and recommendations for ongoing review.
* Ensure all parts of the document, especially the table, are correctly formatted in Markdown.
* After drafting each major section, ask for my review before proceeding to the next.

---

## Phase 6: Review and Conclusion of the Exercise (User to Gemini)

**User Prompt to Gemini:** Once the full draft of the threat model document is complete:
* Ask me to review the entire document for accuracy, clarity, and completeness.
* Ask if there are any outstanding points or if we can formally conclude this threat modeling exercise.

# Website Update Workflows

This README explains the two main maintenance workflows for the website:

1. **Weekly / ongoing research updates**  
   For new hot topics, recent papers, and evolving research-watch entries.

2. **Static research updates**  
   For adding permanent pages to the `Research` section.

---

# Repository structure

```text
AISecurityResearch/
  index.html
  ongoing-work.html
  research.html
  assets/
  posts/
  weekly-inputs/
  ai-security/
  ai-foundations/
  _internal/

Useful folders:

posts/ → full standalone pages for weekly/ongoing research topics
weekly-inputs/ → filled DOCX inputs for weekly automation
ai-security/ → static security topic pages
ai-foundations/ → static technical foundation pages
_internal/ → internal templates and instructions only
Part 1 — Weekly / ongoing research update workflow

Use this workflow when you want to add a new paper or hot topic to:

homepage research-watch area
ongoing-work.html
posts/YYYY-MM-topic-name.html
What this workflow updates automatically

From one filled DOCX, the Jupyter notebook updates:

index.html
ongoing-work.html
posts/YYYY-MM-topic-name.html
Required files

Keep these in your repo:

index.html
ongoing-work.html
posts/
weekly-inputs/
update_ongoing_work_and_home_from_docx_posts_consistent_fixed.ipynb
Weekly workflow steps
1. Go to repo root

Open Git Bash and move to the repo root:

cd /c/Users/Brojogopal.Sapui/Documents/personal_work/Git_workspace/AISecurityResearch
2. Pull latest changes first

Do this before editing anything:

git pull origin main

Important rule:

If you have not started editing yet → pull first
If you already changed files locally → do not pull first; finish, commit, then push
3. Get one research paper

You may keep the PDF locally in:

papers_articles/

The PDF does not need to be pushed to GitHub unless you explicitly want that.

4. Ask ChatGPT to fill the DOCX template

Prompt idea:

I am attaching one research paper PDF and my weekly research watch template DOCX. Fill the DOCX in the required format so that my notebook can parse it and generate the new website update.

Save the filled DOCX in:

weekly-inputs/

Use this naming style:

YYYY-MM-topic-name.docx

Example:

weekly-inputs/2026-03-stack-safeguard-pipelines.docx

This filename is important because the notebook uses the filename stem to keep naming consistent.

5. Run the Jupyter notebook

Open this notebook from the repo root:

update_ongoing_work_and_home_from_docx_posts_consistent_fixed.ipynb

Run all cells.

The notebook will automatically:

pick the latest dated DOCX from weekly-inputs/
update index.html
update ongoing-work.html
create/update a matching post page in posts/

Example generated post:

posts/2026-03-stack-safeguard-pipelines.html
6. Check locally

Open these files from the repo root:

index.html
ongoing-work.html
the new file in posts/

Check that:

homepage Research Watch is updated
ongoing-work note appears at the top
accordion expands properly
full post page exists
links work
7. Check Git changes
git status

Usually you will see changes in:

index.html
ongoing-work.html
posts/YYYY-MM-topic-name.html
weekly-inputs/YYYY-MM-topic-name.docx
8. Add only the needed files

Example:

git add index.html
git add ongoing-work.html
git add posts/2026-03-stack-safeguard-pipelines.html
git add weekly-inputs/2026-03-stack-safeguard-pipelines.docx

Usually you do not need to add:

notebook .ipynb file, unless you changed notebook code
.ipynb_checkpoints/
raw PDF paper
template DOCX
9. Commit

Use a clear message:

git commit -m "Add weekly research watch on STACK safeguard pipeline attacks"

Suggested commit message format:

Add weekly research watch on [topic]

Examples:

Add weekly research watch on embodied AI security and governance
Add weekly research watch on STACK safeguard pipeline attacks
10. Push
git push origin main

Then wait a little and refresh your site.

A hard refresh helps:

Ctrl + Shift + R
Best naming convention for weekly updates

Use the same stem everywhere:

DOCX input
weekly-inputs/2026-03-stack-safeguard-pipelines.docx
Generated full post
posts/2026-03-stack-safeguard-pipelines.html
Post ID
2026-03-stack-safeguard-pipelines

This keeps the whole system consistent.

Very short memory version

Each week:

git pull origin main
get paper
ask ChatGPT to fill the DOCX template
save DOCX in weekly-inputs/YYYY-MM-topic-name.docx
run notebook
check index.html, ongoing-work.html, and posts/...html
git status
git add only needed files
git commit -m "..."
git push origin main
Part 2 — Static research update workflow

Use this when you want to update the permanent Research section.

There are two cases:

add one new file inside an existing section
add a completely new section with multiple files
Case A — Add one new file inside an existing section

Examples:

add one new page inside ai-security/
add one new page inside ai-foundations/
Workflow steps
1. Go to repo root
cd /c/Users/Brojogopal.Sapui/Documents/personal_work/Git_workspace/AISecurityResearch
2. Pull latest changes first
git pull origin main
3. Decide which section it belongs to
If it is a direct security topic

Put it in:

ai-security/

Examples:

ai-security/model-supply-chain-security.html
ai-security/multi-agent-trust-boundaries.html
If it is a technical foundation page

Put it in:

ai-foundations/

Examples:

ai-foundations/on-chip-communication-ai-accelerators.html
ai-foundations/memory-compute-balance.html
4. Create the new file

Create the new page file in the correct folder.

Example:

ai-foundations/on-chip-communication-ai-accelerators.html

Use your internal template/reference files from _internal/ if needed.

5. Edit the content

Update:

title
meta description
heading
introduction
overview section
significance section
image path
discussion blocks
CTA links

If needed, add image to:

assets/img/
6. Make it visible in research.html

Open:

research.html

Then:

If it belongs to ai-security/

Find the section:

Core Security Domains

Add one new card there.

If it belongs to ai-foundations/

Find the section:

AI Foundations

Add one new card there.

Example card
<a class="section-card" href="ai-foundations/on-chip-communication-ai-accelerators.html">
  <h3>On-Chip Communication in AI Accelerators</h3>
  <p>
    A systems-level view of internal data movement, NoC behavior, bandwidth sharing,
    and why communication structure matters for hardware-aware AI security analysis.
  </p>
</a>
7. Check locally

Open:

research.html
the new page itself

Check:

card appears in correct section
link works
page styling is correct
image path works
8. Check Git status
git status

Usually you will see:

research.html
your new page file
optional new image file
9. Add only needed files

Example:

git add research.html
git add ai-foundations/on-chip-communication-ai-accelerators.html
git add assets/img/on-chip-communication-ai-accelerators.png
10. Commit
git commit -m "Add foundation page on on-chip communication in AI accelerators"
11. Push
git push origin main
Very short memory rule for Case A

Add one new static page:

git pull origin main
create new file in correct folder
edit content
add one new card in research.html
check locally
git status
git add
git commit
git push
Case B — Add a completely new section with multiple files

Examples:

new section like AI Systems
new section like Deployment Foundations
new section like AI Trust Basics

This is bigger than adding one page.

Workflow steps
1. Go to repo root
cd /c/Users/Brojogopal.Sapui/Documents/personal_work/Git_workspace/AISecurityResearch
2. Pull latest changes first
git pull origin main
3. Decide the new section name

Examples:

ai-systems/
deployment-foundations/
ai-trust-basics/

Use:

lowercase
hyphens
clear meaning
4. Create the new folder

Example:

ai-systems/
5. Create the files inside that folder

Example:

ai-systems/model-serving-basics.html
ai-systems/runtime-orchestration.html
ai-systems/inference-latency-bottlenecks.html

You can start with 2–3 files first.

6. Write each page

For each file:

use the same page style/template
write title, intro, overview, significance, discussion, CTA
add images if needed
7. Add the new section block in research.html

Open:

research.html

Find this comment already kept there:

<!-- ===== TEMPLATE: ADD A COMPLETELY NEW RESEARCH SECTION BELOW THIS LINE ===== -->

Paste your new section below that comment.

Example structure
<section class="section">
  <div class="container">
    <div class="section-head reveal">
      <span class="eyebrow">AI Systems</span>
      <h2>Systems-level concepts shaping AI deployment and security</h2>
      <p>
        These pages explain the systems concepts behind runtime orchestration,
        model serving, resource scheduling, and deployment behavior that influence
        real AI trust and security.
      </p>
    </div>

    <div class="card-grid three">
      <a class="section-card" href="ai-systems/model-serving-basics.html">
        <h3>Model Serving Basics</h3>
        <p>
          A practical view of serving pipelines, request handling, batching,
          and deployment behavior in modern AI systems.
        </p>
      </a>

      <a class="section-card" href="ai-systems/runtime-orchestration.html">
        <h3>Runtime Orchestration</h3>
        <p>
          How runtimes schedule, coordinate, and control AI execution across devices and services.
        </p>
      </a>

      <a class="section-card" href="ai-systems/inference-latency-bottlenecks.html">
        <h3>Inference Latency Bottlenecks</h3>
        <p>
          An overview of where latency comes from in practical AI inference systems and why it matters.
        </p>
      </a>
    </div>
  </div>
</section>
8. Check locally

Open:

research.html
all new files in the new folder

Check:

new section appears in right place
all cards work
all pages open correctly
styling is consistent
9. Check Git status
git status

Usually you will see:

research.html
all new HTML files
optional new images
10. Add all needed files

Example:

git add research.html
git add ai-systems/model-serving-basics.html
git add ai-systems/runtime-orchestration.html
git add ai-systems/inference-latency-bottlenecks.html
git add assets/img/model-serving-basics.png
11. Commit
git commit -m "Add AI Systems section with initial pages"
12. Push
git push origin main
Very short memory rule for Case B

Add one new big section:

git pull origin main
create new folder
create multiple HTML files inside it
add new section block in research.html
check locally
git status
git add
git commit
git push
Difference between the two static cases
Case A — add one new page inside an existing section

Change:

one new file
one new card in research.html
Case B — add a completely new section

Change:

one new folder
multiple new files
one new section block in research.html
Useful folder logic
Static security pages
ai-security/
Static technical foundation pages
ai-foundations/
Future new static sections
ai-systems/
deployment-foundations/
ai-trust-basics/
Weekly evolving content
posts/
weekly-inputs/
ongoing-work.html
index.html
Internal reference files

Recommended files inside:

_internal/

Examples:

_internal/template-research-reference.txt
_internal/template-post-reference.txt
_internal/_README_add-new-section.txt

These are for internal use only.

Do not add them to navigation.
Do not link them on the website.

Final quick summary
Weekly dynamic update

Use:

DOCX
notebook
updates index.html, ongoing-work.html, posts/...html
Static research update

Use:

manual page creation
manual research.html card/section update
then git add / commit / push

WEBSITE MAINTENANCE README
Internal reference only. Do not link this file from the website.

====================================================
1. HOW TO ADD ONE NEW PAGE INSIDE AN EXISTING SECTION
====================================================

Example:
- add one new page inside ai-foundations/
- add one new page inside ai-security/
- add one new weekly post inside posts/

A. Create the new file
Example:
ai-foundations/your-new-topic.html

B. If needed, copy from the internal template reference
Examples:
_internal/template-post-reference.txt
_internal/template-research-reference.txt

C. Add one new card or link in the correct page
Examples:
- research.html  -> for ai-security/ or ai-foundations/ pages
- ongoing-work.html -> for posts/ pages

Rule:
New page = create file + add visible card/link

====================================================
2. HOW TO ADD A COMPLETELY NEW BIG SECTION IN research.html
====================================================

Example:
- AI Foundations
- AI Systems
- Deployment Foundations
- AI Trust Basics

You must do 3 things:

A. Add a new <section> block in research.html

B. Create a new folder matching that section
Examples:
ai-foundations/
ai-systems/
deployment-foundations/

C. Create the HTML files linked by that section cards

Rule:
New big section = section block + new folder + linked files

====================================================
3. WHERE TO FIND THE TEMPLATE INSIDE research.html
====================================================

Open:
research.html

Look for this comment:

<!-- ===== TEMPLATE: ADD A COMPLETELY NEW RESEARCH SECTION BELOW THIS LINE ===== -->

Paste your new section block below that comment.

====================================================
4. HOW TO ADD ONE NEW FOUNDATION PAGE
====================================================

A. Create new file:
ai-foundations/your-new-topic.html

B. Open:
research.html

C. Find the section:
AI Foundations

D. Copy the commented template card already written there and paste it below the last card

Example:

<a class="section-card" href="ai-foundations/your-new-topic.html">
  <h3>Your New Foundation Topic</h3>
  <p>
    Write a short 2-3 line description explaining why this technical concept matters
    for deeper AI security analysis.
  </p>
</a>

====================================================
5. HOW TO ADD ONE NEW SECURITY PAGE
====================================================

A. Create new file:
ai-security/your-new-security-topic.html

B. Open:
research.html

C. Find:
Core Security Domains

D. Add one new security topic card there

====================================================
6. HOW TO ADD ONE NEW WEEKLY / MONTHLY POST
====================================================

A. Create new file:
posts/2026-03-your-topic.html

B. Copy content from:
_internal/template-post-reference.txt

C. Open:
ongoing-work.html

D. Find the watch-stack section

E. Copy the commented accordion template already placed there

F. Paste it ABOVE the first existing watch-note

G. Add your new post link inside watch-inline-links if you created a full post page

Rule:
New weekly post = create post file + add accordion note in ongoing-work.html

====================================================
7. INTERNAL REFERENCE FILES TO KEEP
====================================================

Keep these files inside:

_internal/

Recommended files:
_internal/template-research-reference.txt
_internal/template-post-reference.txt
_internal/_README_add-new-section.txt

These are for internal use only.
Do not add them to navigation.
Do not link them on the website.

====================================================
8. PUBLIC CONTENT LOCATIONS
====================================================

Static security pages:
ai-security/

Static technical foundation pages:
ai-foundations/

Dynamic weekly/monthly posts:
posts/

Main listing page for research sections:
research.html

Main listing page for ongoing updates:
ongoing-work.html

====================================================
9. QUICK MEMORY RULE
====================================================

If adding one new page:
- create file
- add card/link

If adding one new big section:
- add section block
- create folder
- create linked files

If adding one new weekly post:
- create post file
- add accordion note in ongoing-work.html
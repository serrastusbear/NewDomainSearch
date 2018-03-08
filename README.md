Started out by reading Xavier Mertens' SANS ISC post on searching for newly registered domains:
https://isc.sans.edu/forums/diary/Tracking+Newly+Registered+Domains/23127/

This approach seemed neat, but rather narrow since it relied on one-to-one dictionary matching in order to find results on interest.

Rather than limit myself to dictionary matches, I decided to look into ways of leveraging Python to find 'similarity' items via several algorithms:
  * Python difflib implementation of Ratcliff Obershelp sequence matching
  * Python editdistance implementation of Levenshtein distance
  * Jaccard similarity

These are all provided as command line switch arguments to the script (s, e, and j respectively) to be run against a provided word list, one record per line.

Result is a list of best-match to lowest-match.

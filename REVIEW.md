# Artifact Review for DECANTeR (ACSAC #71)

- I evaluated DECANTeR by running a sample subset of the PCAPs provided by the authors separately from the repository. The results from this subset support the results reported, which reports the entire dataset of 106 PCAP files (see the paper, Table 1, Table 2 and Table 3).
  - These PCAPs were not included in the repository for public distribution because they contain Personally Identifiable Information (PII) (see the paper, Section 4.1).
- I evaluated the authors implementation of Dumont using the provided [example.py](./dumont/example.py), which is discussed in-depth in the [Dumont README](./dumont/README.md).
- I've provided a brief summary of suggestions that I'd make for the authors to improve their artifact for broad usage by the research community below.
- **I recommend this artifact for evaluation acceptance by the committee.**

## Test Environment

| Specification     |                     |
|-------------------|---------------------|
| CPU               | Intel Core i7-7700  |
| Memory            | 64 GiB              |
| Operating System  | Ubuntu 16.04 LTS    |
| Kernel            | 4.4.0-93-generic    |
| Python            | 2.7.12 (aptitude)   |
| Pip               | 9.0.1 (aptitude)    |
| Bro               | 2.5.1 (aptitude)    |

## Suggestions

- Instead of only example commands, also provide a usage statement, ideally using the [POSIX standard format](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html). The example commands given require the listed files to be present in the repository.
- Although you can't release the entire PCAP dataset, it might be helpful to provide an actual _example.pcap_ that has been sanitized of PII but still contains enough data to demostrate DECANTeR.
- Consider using your repository's [Github Wiki](https://help.github.com/articles/about-github-wikis/) for documentation:
  - DECANTeR's API (you've already identified such documentation as a TODO).
  - How to interpret the DECANTeR output from [main.py](./main.py).

---

## Review of DECANTeR

The subsections and quotations below refer to DECANTeR's [README.md](README.md)

### Prerequisites

> Before installing the DECANTeR package, make sure the following python packages are installed:

Note that instructions presume that `Python 2.7` and `pip` are installed. Pip must be upgraded before attempting to install DECANTeR's python package dependencies. I did not upgrade Pip at first and had issues with installing DECANTeR's dependencies later. I added this to the README in my fork request.

> To use our implementation of DECANTeR, you need to transform the .pcap files in bro .log files. Therefore, you need to install [bro](https://www.bro.org/download/packages.html) with its [dependencies](https://www.bro.org/sphinx/install/install.html).

From the second installation instructions link, are both _Required Dependencies_ and _Optional Dependencies_ needed for DECANTeR, or just _Required Dependencies_? I only installed _Required Dependencies_. It seems to work.

### Generating Bro log files

> Run the following command to generate a bro .log file that is parsable by our implementation of DECANTeR.

This example command stumped me for a few moments as someone who was not familiar with Bro before evaluating your artifact. Once I realized that the PCAP dataset you provided me contained examples of the files you meant by _example.pcap_, I was able to figure it out. See my suggestion above to use POSIX-style usage statements.

Although you can't release the entire PCAP dataset, it might be helpful to provide an actual _example.pcap_ that has been sanitized of PII but still contains enough data to demostrate DECANTeR.

> decanter.log" is the log file parsable by our implementation.

This appears to have accidentally been mangled by commit [9547789](https://github.com/rbortolameotti/decanter/commit/9547789715c4a946916a89c8d0acbe9cc17eb3a8#diff-04c6e90faac2675aa89e2176d2eec7d8). I tried to restore it as faithfully as possible.

We also had a discussion via email where Thijs helpfully noted:

> ...  the command `bro -r example.pcap decanter_dump_input.bro` will always write to the file decanter.log, we had to rename them to avoid overwriting existing files.

I added this comment to the README.

Finally, you'll also note that I added the files produced as a side effect of this command to your .gitignore in my pull request. I did this so that pull requests don't pollute the repository.

### DECANTeR Functionalities

> At the current stage, our implementation provides two type of analysis:

My pull request suggests using level four subtitles to make it easier to follow. If you don't like this styling, feel free to roll back that part of the commit.

However, either way, I suggest that you make it clear that the testing and training files you have already provided all needed files for this section in the repository under [test-data/](./test-data/). As we discussed in our email chain, it wasn't readily apparent that they were available already, and I gave Riccardo a bit of a scare. Apologies!

As with _Generating Bro log files_, I added the output files from each of the functionality tests to your .gitignore in order to avoid polluting the repository.

---

## Review of Dumont

There is also an implementation of [Dumont](https://doi.org/10.1109/EC2ND.2011.12) in this repository. After I attempted to produce a minimal demonstration script from the example code at the conclusion of [README.md](./dumont/README.md), the authors provided a working script and sample data to demonstrate the output.

I highly recommend the authors keep this useful, working example in the final repository, and I copied part of its documentation to the top-level [README.md](./dumont/README.md) in order to alert future repository users that the example is in there.

As Dumont produced matching output to their DECANTeR output for a fixed input, I am confident that that their comparison between the two is valid.

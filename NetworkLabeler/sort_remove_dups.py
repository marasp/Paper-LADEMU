import re


def sort_remove_duplicates(in_commentsfile, out_commentsfile):
    infile = in_commentsfile
    outfile = open(out_commentsfile, "w")

    lines_seen = set()  # set() # holds lines already seen

    with open(infile, "r") as f:
        lines = f.readlines()
        for line, r in enumerate(lines):
            try:
                thisLine = lines[line]
                nextLine = lines[line + 1]
                prevLine = lines[line - 1]
            except IndexError:
                pass

            label = thisLine.split(":")[-1]
            framenum = thisLine.split(":")[0].split("-a ")[-1]

            attack_regex = f"^\-[a]\s[{framenum}]*\:(((?!T1071.001))[T]([0-9]*\.[0-9]*|[0-9]*))\s?$"
            c2_regex = f"^\-[a] [{framenum}]*\:(T1071.001) ?$"

            if framenum not in lines_seen:
                if (re.match(c2_regex, thisLine) and re.match(attack_regex, nextLine)):
                    pass
                elif (re.match(attack_regex, thisLine) and re.match(c2_regex, nextLine)):
                    outfile.write(thisLine)
                    lines_seen.add(framenum)
                else:
                    outfile.write(thisLine)
                    lines_seen.add(framenum)

            elif framenum in lines_seen:
                if (re.match(c2_regex, thisLine) and re.match(attack_regex, prevLine)):
                    pass
                elif (re.match(attack_regex, thisLine) and re.match(c2_regex, prevLine)):
                    outfile.write(thisLine)
                    lines_seen.add(framenum)
                else:
                    pass

            else:
                outfile.write(thisLine)
                lines_seen.add(framenum)

        outfile.close()
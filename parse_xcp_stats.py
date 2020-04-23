#!/usr/local/bin/python
# 
# Parse multiple output files from xcp.exe SMB scan -stats
# Also supports parsing the cataloged .csv files from XCP NFS scan -newid
# Usage:
#   python parse_xcp_stats.py [files]
# Files should be all windows SMB or all NFS; no mixing.

import sys
import json
from collections import Counter, OrderedDict
from numbers import Number

# For the histograms
# Example from xcp.exe output on windows (SMB):
#
# == Top File Extensions ==
# 	  .zip       .pdf       .xls        .gz      .xlsx       .svg      other
# 	 19507      16328      15786       9506       4554       3108      22047
#
# == Space used ==
#      empty      <8KiB    8-64KiB 64KiB-1MiB    1-10MiB  10-100MiB    >100MiB
#          0    24.2MiB     680MiB    13.2GiB    34.2GiB    33.5GiB     159GiB
#
# Example from csv file on Linux (NFS)
# Number of files,empty,<8KiB,8-64KiB,64KiB-1MiB,1-10MiB,10-100MiB,>100MiB
# Number of files,590,134389,159384,172188,59193,10008,1470
# Space used,empty,<8KiB,8-64KiB,64KiB-1MiB,1-10MiB,10-100MiB,>100MiB
# Space used,1052160,4890359296,20334654464,97270969856,251547222528,308987934720,872737029632


MaxField = 9

Histograms = (
	"Maximum Values",
	"Average Values",
	"Space used",
	"Top File Extensions",
	"Number of files",
	"Directory entries",
	"Depth",
	"Modified",
	"Created", # SMB
	"Changed", # NFS
)

SingleValues = (
	"Total space used",
	"Total count",
	"Total space for regular files",
	"Regular files",
	"Directories",
	"Total space for directories",
	"Symbolic links",
	"Junctions",
	"Special files",
)

SingleValueOutputs = OrderedDict([
	("Total space used", "Total space"),
	("Regular files", "File count"),
	("Directories", "Dir count"),
	("Symbolic links", "Symlinks"),
	("Junctions", "Junctions"),  # SMB
	("Hard links", "Hard links"), # NFS
	("Special files", "Specials"),
])

lineNum = None

def convert(val):
	sizes = {'KiB': 1<<10, 'MiB': 1<<20, 'GiB': 1<<30, 'TiB': 1<<40}
	counts = {'K': 10**3, 'M': 10**6, 'B': 10**9, 'T': 10**12}

	orig = val.strip()
	v = val.replace(',', '').strip()

	if v.strip() == '':
		return orig, 0

	for s, n in sizes.items():
		if v.endswith(s):
			return orig, int(float(v.rstrip(s)) * n)

	for s, n in counts.items():
		if v.endswith(s):
			return orig, int(float(v.rstrip(s)) * n)

	return orig, int(v)

def getfields(line1, line2):
	if ">1 year" in line1:
		# there are spaces here so just special-case it
		names = [">1 year", ">1 month", "1-31 days", "1-24 hrs", "<1 hour", "<15 mins", "future", "invalid"]
	else:
		names = line1.split()

	values = []
	for name in names:
		# The values are right justified underneath the column name
		i = line1.index(name) + len(name) - MaxField
		s, n = convert(line2[i:i+MaxField])
		values.append(n)

	return names, values

class Histo(object):
	def __init__(self, title, labels, values):
		self.title = title
		self.labels = labels
		self.values = values

class ScanStats(object):
	def __init__(self, fileName, lines):
		self.fileName = fileName
		self.hists = {}
		self.single = {}
		self.source = None
		self.nError = 0
		global lineNum

	@classmethod
	def fromFile(cls, fileName, f):
		if fileName.endswith('csv'):
			return ScanStats.fromCSV(fileName, f)
		# If it's not json; assume it's the windows output
		return ScanStats.fromWindows(fileName, f)

	@classmethod
	def fromWindows(cls, fileName, f):
		self = cls(fileName, f)
		lines = f.readlines()
		for lineNum, line in enumerate(lines):
			if line.startswith("xcp scan"):
				self.source = next(f for f in line.split() if f.startswith("\\"))
				continue

			if " errors, " in line:
				errfield = next(f for f in line.split(',') if "errors" in f)
				nErr, _ = errfield.split()
				nErr = int(nErr)
				self.nError = max(self.nError, nErr)

			title = line.strip().lstrip("== ").rstrip(" ==")

			if title in Histograms:
				labels, values = getfields(lines[lineNum+1], lines[lineNum+2])
				self.hists[title] = Histo(title, labels, values)
				continue
			title, _, s = line.partition(':')
			if title in SingleValueOutputs:
				s, n = convert(s)
				self.single[title] = n
		return self

	@classmethod
	def fromCSV(cls, fileName, f):
		self = cls(fileName, f)
		lines = f.readlines()
		self.skip1 = None
		for lineNum, line in enumerate(lines):
			if self.skip1:
				assert line.startswith(self.skip1)
				self.skip1 = None
				continue

			self.skip1 = None
			if line.startswith("scan "):
				self.source = line.split()[1]
				continue

			# summary,"1.52M scanned, 1.51M indexed, 860 errors, 325 MiB in (1.10 MiB/s), 102 MiB out (355 KiB/s), 4m54s."

			if line.startswith('summary,"'):
				if "errors," in line:
					# Get the words inside the quotes
					fields = line[len('summary,"'):-1].split()
					# The number of errors is the field before "errors,"
					self.nError = int(fields[fields.index("errors,")-1])
					continue

			fields = line.split(',')
			if not fields:
				continue

			title = fields[0]
			if title in Histograms:
				# Histograms have the names in one line and values in the other.  Example:
				# Maximum Values,Size,Used,Depth,Namelen,Dirsize
				# Maximum Values,14579924992,19489326592,19,162,8166
				labels = fields[1:]
				values = lines[lineNum+1].split(',')[1:]
				#print("title: {} names {} values {}".format(title, names, values))
				self.hists[title] = Histo(title, labels, values)
				self.skip1 = title
				continue

			if title not in SingleValueOutputs:
				continue
			# Single-value stats.  Example:
			# Total count,587405
			self.single[title] = int(fields[1])
			# Note there are a couple oddball single stats lines with multiple values.  Example:
			# Total space for regular files,size,1220499115378,used,1555769222656
			# These could be parsed but they are not in SingleValueOutputs

		return self

if __name__ == "__main__":
	fileNames = sys.argv[1:]
	file2stats = {}

	for fileName in fileNames:
		try:
			with open(fileName) as f:
				# Get the histogram values and the individual stat single for each file
				file2stats[fileName] = ScanStats.fromFile(fileName, f)
		except Exception as e:
			if lineNum:
				print("** {}: error on or near line {}".format(fileName, lineNum+1))
			raise

	# Create lists for the two header rows
	# First three columns are for file name, error count, and share name
	header0 = ['', '', '']
	header = ['', 'Errors', '']
	for colName in SingleValueOutputs:
		header0.append('')
		header.append(colName)

	for title in Histograms:
		# The histogram label list is the same for all files
		# except for top file extensions
		if title == "Top File Extensions":
			continue
		# Get the label list (arbitrarily get it from the first file's stats)
		stats0 = file2stats[fileNames[0]]
		if title not in stats0.hists:
			# linux is missing "Created" and windows is missing "Changed"
			# so just skip it
			continue

		labels = stats0.hists[title].labels
		# header0 has the title of the histogram (e.g. "Space used"),
		# followed by empty fields.  Header has the actual labels, e.g.
		# ""
		header0.append(title)
		header0.extend(['']*(len(labels)-1))
		header.extend(labels)

	# Add a row for each file
	rows = []
	for fileName in fileNames:
		stats = file2stats[fileName]

		# Start the row with 3 fields and then append the single-value stats and the histogram values
		errCount = stats.nError or ''
		row = [fileName, errCount, stats.source]
		rows.append(row)

		# Add the value in each column for the single-value stats
		row.extend(list(stats.single.get(title) for title in SingleValueOutputs.keys()))

		for title in Histograms:
			# The top file extensions are the labels, so 
			# the labels are different for each file.
			if title == "Top File Extensions":
				# TODO: provide a separate report for these
				continue
			# The Create histogram doesn't exist on NFS
			# The Change histogram doesn't exist on SMB
			# So just skip anything that's not there (also skipped above in header row)
			if title in stats.hists:
				row.extend(stats.hists[title].values)

	outFileName = 'stats.csv'

	print("Processed {} files; {} had errors; saving csv in {}".format(
		len(fileNames),
		sum(1 for name in fileNames if file2stats[name].nError),
		outFileName
	))

	# Sort by space used (4th column)
	rows.sort(key=lambda row: row[3], reverse=True)
	with open(outFileName, 'wb') as f:
		def fmt(item):
			if isinstance(item, Number):
				return str(item)
			return '"{}"'.format(item)

		def mkline(row):
			s = ','.join(fmt(item) for item in row)
			return s + '\n'
		
		f.write(mkline(header0))
		f.write(mkline(header))
		for n, r in enumerate(rows):
			f.write(mkline(r))

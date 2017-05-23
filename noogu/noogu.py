import re

def lines_from(text):
	""" Returns list of cleaned lines for whois queries """
	dots = re.compile(r'\.{2,}')
	dashes = re.compile(r'-{2,}')
	lines = [dots.sub(':',t.strip()) for t in text.split('\n')]
	lines = [re.sub(r'\[(.*?)\]',r'\1:',line) if not (line.endswith(']') and not line.startswith('[')) else line for line in lines]
	lines = [line for line in lines if not line.startswith('%')]
	lines = [line for line in lines if not line.startswith('#')]
	lines = [line for line in lines if not line.startswith('>>>')]
	return lines

def tweak_keys(section,subsection):
	""" Return adjusted section and key names 

	There are plans to make this into one big dictionary,
	which you can see here 

	Need to add: Subsection may take precedence over section 
	"""
	# Large dictionaries
	section_dict = {
		# co.jp
		# 'Domain Information': 'Registrant',

		# .sg
		# 'Administrative Contact': 'admin',
		# 'Technical Contact': 'tech',
		# 'Name Servers': 'nameservers',

		# # .de
		# 'Tech-C': 'tech',
		# 'Zone-C': 'registrant',

		# # .eu
		# 'Technical': 'tech',
		# 'Name servers': 'nameservers',

		# .fr
		'tech-c':'tech',
		'holder-c':'registrant',
		'admin-c':'admin',

		# # .com

		# # .edu
		# 'Administrative Contact':'admin',
		# 'Registrant':'registrant',
		# 'Technical Contact':'tech'

	}

	subsection_dict = {
		'Nserver':'nameserver',
		
		# co.jp
		'Organization':'org',
		'Organization Type':'org_type',
		'Administrative Contact':'admin_name',
		'Technical Contact':'tech_name'
	}

	# Section adjustments
	if section == 'Domain Information':
		# co.jp 
		if re.search(r'Admin',subsection,re.IGNORECASE):
			new_section = 'admin'
		if re.search(r'Technical',subsection,re.IGNORECASE):
			new_section = 'tech'
		else:
			new_section = 'registrant'

	elif section in list(section_dict):
		new_section = section_dict.get(section)

	elif section:
		if re.search(r'admin',section,re.IGNORECASE):
			new_section = 'admin'
		elif re.search(r'tech',section,re.IGNORECASE):
			new_section = 'tech'
		elif re.search(r'name ?server',section,re.IGNORECASE):
			new_section = 'nameservers'
		elif re.search(r'registrant',section,re.IGNORECASE):
			new_section = 'registrant'
		elif re.search(r'registrar',section,re.IGNORECASE):
			new_section = 'registrar'
	else:
		# Check subsection
		if re.search(r'admin',subsection,re.IGNORECASE):
			new_section = 'admin'
		elif re.search(r'tech',subsection,re.IGNORECASE):
			new_section = 'tech'
		elif re.search(r'registrant',subsection,re.IGNORECASE):
			new_section = 'registrant'
		elif re.search(r'registrar',subsection,re.IGNORECASE):
			new_section = 'registrar'
		else:
			new_section = section

	# subsection adjustments
	if re.search(r'organization|organisation|contact',subsection,re.IGNORECASE):
		if re.search(r'type',subsection,re.IGNORECASE):
			new_subsection = 'org_type'
		else:
			new_subsection = 'org'
	elif re.search(r'name|person', subsection,re.IGNORECASE):
		if re.search(r'server',subsection,re.IGNORECASE):
			new_subsection = 'nameserver'
		else:
			new_subsection = 'name'
	elif re.search(r'address', subsection,re.IGNORECASE):
		new_subsection = 'address'
	else:
		new_subsection = subsection

	return new_section, new_subsection

def guess_buffer(lines):
	# sanitize
	lines = [line.strip() for line in lines if line.strip()!='']
	has_num = [re.search('\d',line) for line in lines]
	has_alph = ['@' in line[0] for line in lines]
	# The first line that contains a number is the beginning of the address line
	# If University name or department name begins with a number, this will be wrong 
	addr_begin = next((line for line in lines if re.search(r'\d',line)),None)
	# Line before address is the organization
	if addr_begin:
		addr_idx = lines.index(addr_begin)
	else:
		addr_idx = 1
	org = lines[addr_idx-1]
	lines.remove(org)
	# Anything before that is the name of the person
	if addr_idx>1: 
		name = lines[:addr_idx-1]
		for n in name:
			lines.remove(n)
		name = '\n'.join(name)
	else:
		name = None

	# The line that contains parentheses is a phone number
	phone = next((line for line in lines if re.search(r'\(\s?\d+\s?\)\s?\d+\s?-\s?\d+\s?',line)),None)
	if phone: lines.remove(phone)
	# The line that contains @ is an email address
	email = next((line for line in lines if re.search(r'@',line)),None)
	if email: lines.remove(email)

	# Send everything else to address?
	address = '\n'.join(lines)

	# Create result
	result = {
		'name':name,
		'phone':phone,
		'email':email,
		'org':org,
		'address':address
	} 
	return result


def noogu(text):
	SECTION = None
	LOOKING = None
	section_buffers = {}
	debug = {}
	inv_debug = {}
	prev_line_blank = False

	lines = lines_from(text)
	for line in lines:
		if prev_line_blank: print("Previous line blank")
		line=line.strip()
		# Sections carry over multiple lines
		new_section = re.search(r'(.*?):$',line)
		if new_section:
			if prev_line_blank:
				SECTION = new_section.group(1)
				print("NEW SECTION")
			else:
				lkey = new_section.group(1)
				lvalue = None


		# Check if there is a : followed by spaces
		LOOKING = re.search(r'(.*?):\s+(.*?)$',line)
		if LOOKING:
			lkey = LOOKING.group(1)
			lvalue = LOOKING.group(2)


			# Check if the key values match any other key values
			if lvalue in list(debug.values()):
				# For FRNIC type whois queries 
				if '-FRNIC' in lvalue:
					SECTION = inv_debug[lvalue]

			# Standardize the keys
			SECTION, lkey = tweak_keys(SECTION, lkey)


			# Name the sections appropriately
			if SECTION:
				KEY = '{}_{}'.format( SECTION, lkey )
				VALUE = lvalue
			else:
				KEY = lkey
				VALUE = lvalue


			# If the same key already exists, append
			if KEY in list(debug):
				VALUE = ';'.join([debug[KEY],VALUE])

			# Add to data 
			debug[KEY] = VALUE
			inv_debug[VALUE] = KEY 

		# If no : (e.g., .edu domains)
		# Need to guess what these correspond to
		elif SECTION!=None:
			SECTION, _throwaway_ = tweak_keys(SECTION,'')
			if SECTION in list(section_buffers):
				section_buffers[SECTION].append(line.strip())
			else:
				section_buffers[SECTION] = [line]
		try:
			print('{}, {}, {}'.format(SECTION,lkey,lvalue))
		except:
			print(line)

		# Note if blank line
		prev_line_blank = line.strip()==''



	# Process the saved buffers
	# print(list(section_buffers))
	if len(section_buffers) > 0:
		for section in list(section_buffers):
			if not re.search(r'name ?server',section,re.IGNORECASE):
				guess = guess_buffer(section_buffers[section])
				for subsection in list(guess):
					debug['{}_{}'.format(section,subsection)] = guess[subsection]
	return debug



def hint_from(line):
	if re.search(r'organization|organisation',line,re.IGNORECASE):
		hint = 'org'
	elif re.search(r'name|person',line,re.IGNORECASE):
		hint = 'name'
	else: 
		hint = None 
	return hint


def whois_from_text(text):
	"""
	When we read whois queries, we first start by ignoring all the information
	then once we reach something like "tech" or "domain information". This 
	toggles the 'LOOKING_FOR' variable

	CURR_SECTION: which section are we currently on? (e.g., admin org)
	PREV_SECTION: which section were we on previously?
	LINE_SECTION: 
	HINT: Does the current line contain 'org' or 'name' or 'address?'

	"""
	CURR_SECTION = 'Start'
	PREV_SECTION = 'Start'
	# What you're looking for carries over within SECTIONs but not across
	LOOKING_FOR = None
	HINT = None
	hints = []
	buffers = {}
	result = {}
	section_buffer = []

	# text = print_whois(splt_alph)
	lines = lines_from(text)

	for line in lines:
		splt_colon = line.split(':')[-1].strip()
		

		# If line contains "Registrar", store that
		if re.search(r'Registrar:',line,re.IGNORECASE):
			result['registrar'] = splt_colon


		# Line IDs do not carry over
		LINE_SECTION = None 
		# HINTs tell us if the line has "organization" or "name" in them
		HINT = hint_from(line) 
		# Get current line status
		for sid in ['Admin','Tech','Registrant','Registrar']:
			if re.search(r'{}'.format(sid),line):
				LINE_SECTION = sid.lower()

		# If detect a line, determine whether to change section
		if LINE_SECTION == None:
			# Since section hasn't changed 
			# Should we do something different here? 
			section_buffer.append(line)
		elif (LINE_SECTION == CURR_SECTION):
			# Section hasn't changed
			section_buffer.append(line)
		elif (LINE_SECTION != CURR_SECTION):
			# Section has changed
			# Dump buffer
			buffers[CURR_SECTION] = section_buffer
			section_buffer = []

			# Update the where we are
			PREV_SECTION = CURR_SECTION
			CURR_SECTION = LINE_SECTION.lower()

			# Clear what we're looking for 
			LOOKING_FOR = None

			# If sections changed and no information
			try:
				any_info = any([PREV_SECTION in x for x in list(result)])
				info_len = len(buffers[PREV_SECTION])
				if (info_len >= 2) & (not any_info) & (PREV_SECTION!='Start'):
					result['{}_name'.format(PREV_SECTION)] = buffers[PREV_SECTION][0]
					result['{}_org'.format(PREV_SECTION)] = buffers[PREV_SECTION][1]
				elif (info_len < 2) & (PREV_SECTION!='Start')&(not any_info):
					result['{}_name'.format(PREV_SECTION)] = result.get('Start_name',pd.np.nan)
					result['{}_org'.format(PREV_SECTION)] = result.get('Start_org',pd.np.nan)


			except Exception as e:
				pass
				# print(str(e))
				# print(buffers[PREV_SECTION])
				# print(PREV_SECTION)

		# Within a section, we are looking for the organization and the name
		# If hint_from is triggered but returns blank, keep looking
		if (hint_from(line)!=None) & (splt_colon==''):
			LOOKING_FOR = hint_from(line)
		# If hint_from is triggered and returns non blanks, stop looking
		elif (hint_from(line)!=None) & (splt_colon!=''):
			LOOKING_FOR = hint_from(line)
			k = '{}_{}'.format(CURR_SECTION,LOOKING_FOR)
			if k in list(result):
				pass
			else:
				result[k] = splt_colon
			LOOKING_FOR = None
		# If hint from is not triggered but is looking for 
		elif (hint_from(line)==None):
			if LOOKING_FOR:
				k = '{}_{}'.format(CURR_SECTION,LOOKING_FOR)
				if k in list(result):
					pass
				else:
					result[k] = splt_colon
			else:
				pass		

		# Remove 'Start' keys
		for key in list(result):
			if 'Start' in key:
				del(result[key])


		# For testing. 
		hints.append((CURR_SECTION,LOOKING_FOR))
	# For testing 
	# result['splt_alph'] = splt_alph
	return result
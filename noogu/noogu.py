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

def tweak_keys(section,candidate):
	""" Guess the appropriate result key name 

	This will update the 
	Need to add: Subsection may take precedence over section 
	"""
	# Large dictionaries
	section_dict = {
		# .fr
		'tech-c':'tech',
		'holder-c':'registrant',
		'admin-c':'admin'
	}

	candidate_dict = {
		'Nserver':'nameserver',
		
		# co.jp
		'Organization':'org',
		'Organization Type':'org_type',
		'Administrative Contact':'admin_name',
		'Technical Contact':'tech_name'
	}

	# Section adjustments
	if section == 'Domain Information':
		status = 'parsing with respect to '
		# co.jp 
		if re.search(r'Admin',candidate,re.IGNORECASE):
			new_candidate = 'admin'
		if re.search(r'Technical',candidate,re.IGNORECASE):
			new_candidate = 'tech'
		else:
			new_candidate = 'registrant'


	elif section in list(section_dict):
		status = 'exception cases'
		new_candidate = section_dict.get(section)


	elif section:
		status = 'section is specified'
		if re.search(r'admin',section,re.IGNORECASE):
			new_candidate = 'admin'
		elif re.search(r'tech',section,re.IGNORECASE):
			new_candidate = 'tech'
		elif re.search(r'name ?server',section,re.IGNORECASE):
			new_candidate = 'nameservers'
		elif re.search(r'registrant',section,re.IGNORECASE):
			new_candidate = 'registrant'
		elif re.search(r'registrar',section,re.IGNORECASE):
			new_candidate = 'registrar'
		else:
			status = 'section specified but not sure what it is'
			print(section)
			new_candidate = section

	else:
		status = 'section == None'
		new_candidate = '' 
		# Check candidate
		if re.search(r'admin',candidate,re.IGNORECASE):
			new_candidate = 'admin'
		elif re.search(r'tech',candidate,re.IGNORECASE):
			new_candidate = 'tech'
		elif re.search(r'registrant',candidate,re.IGNORECASE):
			new_candidate = 'registrant'
		elif re.search(r'registrar',candidate,re.IGNORECASE):
			new_candidate = 'registrar'
		else:
			new_candidate = ''

	# Extract our new candidate from input candidate
	candidate = re.sub(r'{}(.*?)'.format(new_candidate),r'\1', candidate, flags=re.I).strip()

	# Match the remaining candidate input
	if re.search(r'organization|organisation|contact',candidate,re.IGNORECASE):
		if re.search(r'type',candidate,re.IGNORECASE):
			new_candidate = ' '.join([new_candidate,'org_type'])
		else:
			new_candidate = ' '.join([new_candidate,'org'])
	elif re.search(r'name|person', candidate,re.IGNORECASE):
		if re.search(r'server',candidate,re.IGNORECASE):
			new_candidate = ' '.join([new_candidate,'nameserver'])
		else:
			new_candidate = ' '.join([new_candidate,'name'])
	elif re.search(r'address', candidate,re.IGNORECASE):
		new_candidate = ' '.join([new_candidate,'address'])
	else:
		new_candidate = ' '.join([new_candidate,candidate])

	return new_candidate.lower().strip()

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


def noogu(text, verbose=False):
	# TODO : 
	# 1. Need to specify when subsection can override sections
	status = None
	section = None
	LOOKING = None
	section_buffers = {}
	result = {}
	inv_result = {}
	prev_line_blank = False

	lines = lines_from(text)
	for line in lines:
		# Section carries over lines and changes only when previous line is 
		# blank, followed by something like "Registrar:"
		# if prev_line_blank: print("Previous line blank")
		line = line.strip() # Do you need this? 
		new_section = re.search(r'(.*?):$',line)
		if new_section:
			if prev_line_blank:
				status = 'found new section'
				section = new_section.group(1)
				print("NEW section")
			else:
				status = 'found empty value'
				result_key = new_section.group(1)
				result_value = None


		# Check if there is a : followed by spaces
		LOOKING = re.search(r'(.*?):\s+(.*?)$',line)
		if LOOKING:
			status = 'found subsection and value'
			result_key = LOOKING.group(1)
			result_value = LOOKING.group(2)


			# Check if the key values match any other key values
			if result_value in list(result.values()):
				# For FRNIC type whois queries 
				if '-FRNIC' in result_value:
					section = inv_result[result_value]

			# Standardize the keys
			#------------------------------------------------------------------
			#
			# This part needs a lot of rethinking
			# 
			# All we need here is to update the result key using the section and result key
			result_key = tweak_keys(section, result_key) 
			VALUE = result_value

			# Name the sections appropriately
			# if section:
			# 	status = 'updating result_key'
			# 	result_key = '{}_{}'.format( section, result_key )
			# 	VALUE = result_value
			# else:
			# 	status = 'no need to update result key'
			# 	result_key = result_key
			# 	VALUE = result_value
			#
			#------------------------------------------------------------------
			# If the same key already exists, append
			if result_key in list(result):
				VALUE = ';'.join([result[result_key],VALUE])

			# Add to data 
			result[result_key] = VALUE
			inv_result[VALUE] = result_key 

		# If no : (e.g., .edu domains)
		# Need to guess what these correspond to
		elif section!=None:
			section, _throwaway_ = tweak_keys(section,'')
			if section in list(section_buffers):
				section_buffers[section].append(line.strip())
			else:
				section_buffers[section] = [line]
		try:
			print('{}, {}, {}'.format(section,result_key,result_value))
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
				for result_key in list(guess):
					result['{}_{}'.format(section,result_key)] = guess[result_key]

	# Add the text to result
	result['raw'] = text
	return result



# def hint_from(line):
# 	if re.search(r'organization|organisation',line,re.IGNORECASE):
# 		hint = 'org'
# 	elif re.search(r'name|person',line,re.IGNORECASE):
# 		hint = 'name'
# 	else: 
# 		hint = None 
# 	return hint


# def whois_from_text(text):
# 	"""
# 	When we read whois queries, we first start by ignoring all the information
# 	then once we reach something like "tech" or "domain information". This 
# 	toggles the 'LOOKING_FOR' variable

# 	CURR_section: which section are we currently on? (e.g., admin org)
# 	PREV_section: which section were we on previously?
# 	LINE_section: 
# 	HINT: Does the current line contain 'org' or 'name' or 'address?'

# 	"""
# 	CURR_section = 'Start'
# 	PREV_section = 'Start'
# 	# What you're looking for carries over within sections but not across
# 	LOOKING_FOR = None
# 	HINT = None
# 	hints = []
# 	buffers = {}
# 	result = {}
# 	section_buffer = []

# 	# text = print_whois(splt_alph)
# 	lines = lines_from(text)

# 	for line in lines:
# 		splt_colon = line.split(':')[-1].strip()
		

# 		# If line contains "Registrar", store that
# 		if re.search(r'Registrar:',line,re.IGNORECASE):
# 			result['registrar'] = splt_colon


# 		# Line IDs do not carry over
# 		LINE_section = None 
# 		# HINTs tell us if the line has "organization" or "name" in them
# 		HINT = hint_from(line) 
# 		# Get current line status
# 		for sid in ['Admin','Tech','Registrant','Registrar']:
# 			if re.search(r'{}'.format(sid),line):
# 				LINE_section = sid.lower()

# 		# If detect a line, determine whether to change section
# 		if LINE_section == None:
# 			# Since section hasn't changed 
# 			# Should we do something different here? 
# 			section_buffer.append(line)
# 		elif (LINE_section == CURR_section):
# 			# Section hasn't changed
# 			section_buffer.append(line)
# 		elif (LINE_section != CURR_section):
# 			# Section has changed
# 			# Dump buffer
# 			buffers[CURR_section] = section_buffer
# 			section_buffer = []

# 			# Update the where we are
# 			PREV_section = CURR_section
# 			CURR_section = LINE_section.lower()

# 			# Clear what we're looking for 
# 			LOOKING_FOR = None

# 			# If sections changed and no information
# 			try:
# 				any_info = any([PREV_section in x for x in list(result)])
# 				info_len = len(buffers[PREV_section])
# 				if (info_len >= 2) & (not any_info) & (PREV_section!='Start'):
# 					result['{}_name'.format(PREV_section)] = buffers[PREV_section][0]
# 					result['{}_org'.format(PREV_section)] = buffers[PREV_section][1]
# 				elif (info_len < 2) & (PREV_section!='Start')&(not any_info):
# 					result['{}_name'.format(PREV_section)] = result.get('Start_name',pd.np.nan)
# 					result['{}_org'.format(PREV_section)] = result.get('Start_org',pd.np.nan)


# 			except Exception as e:
# 				pass
# 				# print(str(e))
# 				# print(buffers[PREV_section])
# 				# print(PREV_section)

# 		# Within a section, we are looking for the organization and the name
# 		# If hint_from is triggered but returns blank, keep looking
# 		if (hint_from(line)!=None) & (splt_colon==''):
# 			LOOKING_FOR = hint_from(line)
# 		# If hint_from is triggered and returns non blanks, stop looking
# 		elif (hint_from(line)!=None) & (splt_colon!=''):
# 			LOOKING_FOR = hint_from(line)
# 			k = '{}_{}'.format(CURR_section,LOOKING_FOR)
# 			if k in list(result):
# 				pass
# 			else:
# 				result[k] = splt_colon
# 			LOOKING_FOR = None
# 		# If hint from is not triggered but is looking for 
# 		elif (hint_from(line)==None):
# 			if LOOKING_FOR:
# 				k = '{}_{}'.format(CURR_section,LOOKING_FOR)
# 				if k in list(result):
# 					pass
# 				else:
# 					result[k] = splt_colon
# 			else:
# 				pass		

# 		# Remove 'Start' keys
# 		for key in list(result):
# 			if 'Start' in key:
# 				del(result[key])


# 		# For testing. 
# 		hints.append((CURR_section,LOOKING_FOR))
# 	# For testing 
# 	# result['splt_alph'] = splt_alph
# 	return result
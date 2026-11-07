# SPDX-License-Identifier: GPL-3.0-or-later
# Modified for current source distribution, 2026-11-07.
"""Build the current U64E2 Beta 5 CFW after validating its exact RAM layout."""
import hashlib
import struct
try:
    from . import image_core as original
    from . import memory_layout as base
except ImportError:
    import image_core as original
    import memory_layout as base
InvalidImage = original.InvalidImage
RAM_START, RAM_END = (original.RAM_START, original.RAM_END)
HEAP_BYTES = 5128192
RESOURCE_BYTES = 1043296
RESOURCE_SHA256 = '20b69f913eeda1d59fe86c7436ec34837edcbcfbd118e91559201485c48d77c3'
SEED_OFFSET = 32
PRODUCER_SYMBOL = 'p18m_ram_profile_initialized_esp_heap'
PROFILE_NAME = 'U64E2_BETA5_RAM'
DMA_START, DMA_END, SLOT_BYTES = (458752, 475136, 8192)
parse_real = base.parse_real

def check_dma(elf):
    parsed = base.parse_real(elf)
    symbols = parsed['symbols']
    for name, value in [('__p17i_wd_dma_start', DMA_START), ('__p17i_wd_dma_end', DMA_END)]:
        base.require(name in symbols and symbols[name]['value'] == value and (symbols[name]['section'] == 65521), 'Missing/extraneous low DMA absolute boundary: ' + name)
    base.require(base.CACHE_END <= DMA_START < DMA_END <= 16777216 and DMA_END - DMA_START == 2 * SLOT_BYTES, 'WD DMA reservation exceeds its reviewed address range')
    for section in parsed['allocated']:
        lo = section['address']
        hi = lo + section['size']
        base.require(hi <= DMA_START or lo >= DMA_END, 'Allocated ELF section overlaps WD DMA slots')
    producer = symbols.get('p17i_wd_dma_profile')
    base.require(producer is not None and producer['size'] == 4 and (producer['info'] >> 4 == 1) and (0 < producer['section'] < len(parsed['sections'])), 'Missing/invalid WD DMA producer')
    section = parsed['sections'][producer['section']]
    base.require(section[2] & 2 and RAM_START <= producer['value'] and (producer['value'] + 4 <= RAM_START + parsed['program_headers'][parsed['load_indices'][0]][4]) and (section[3] <= producer['value']) and (producer['value'] + 4 <= section[3] + section[5]), 'WD DMA producer escaped allocated high file bytes')
    offset = section[4] + producer['value'] - section[3]
    raw = base.original.bounded(elf, offset, 4, 'WD DMA producer')
    base.require(struct.unpack('<I', raw)[0] == 1345402697, 'Wrong WD DMA producer value')
    return {'start': DMA_START, 'end_exclusive': DMA_END, 'slot_bytes': SLOT_BYTES, 'slots': 2, 'maximum_dma_address_exclusive': 16777216, 'loader_writes_low_dma': False, 'runtime_low_dma_writes': True, 'reservation_kind': 'checked absolute symbols; no extra LOAD'}

def prepare(elf):
    low_dma = check_dma(elf)
    normalized, parsed, routing = base.normalize_elf(elf)
    symbols = parsed['symbols']
    producer = symbols.get(PRODUCER_SYMBOL)
    original.require(producer is not None and producer['info'] >> 4 == 1 and ((producer['value'], producer['size'], producer['section']) == (HEAP_BYTES, 0, 65521)), 'embedded ESP initialized heap ABS producer missing or mismatched')
    for previous in ('p18f_ram_profile_log_stream_heap', 'p18d_ram_profile_log_heap', 'p17d_ram_profile_full_sp521'):
        original.require(previous not in symbols, 'ambiguous conflicting heap producer')
    resource = base.check_initialized_heap(elf, parsed['loads'][0], parsed['sections'], parsed['allocated'], symbols)
    return (normalized, parsed, routing, low_dma, resource)

def decorate(report, parsed, routing, low_dma, resource):
    report['memory_profile'] = profile_routing()
    report['physical_load_normalization'] = routing
    report['real_allocated_sections'] = parsed['allocated']
    report['wd_dma'] = low_dma
    report['embedded_esp_resource'] = resource
    report['scope'] = 'Actual embedded ESP initialized heap, exact raw ESP image and preconstructor claim; retained strict high-RAM/cached-SP/DMA/APP/CFW checks; no hardware execution claim.'
    return report

def inspect_elf(elf):
    normalized, parsed, routing, low_dma, resource = prepare(elf)
    report, payload = original.inspect_elf(normalized)
    original.require(payload == parsed['payload'], 'strict guard changed physical payload')
    return (decorate(report, parsed, routing, low_dma, resource), payload)

def build_cfw(elf, app):
    normalized, parsed, routing, low_dma, resource = prepare(elf)
    cfw, report = original.build_cfw(normalized, app)
    report['elf_sha256'] = hashlib.sha256(elf).hexdigest()
    return (cfw, decorate(report, parsed, routing, low_dma, resource))

def profile_routing():
 return {'name':PROFILE_NAME,'heap_bytes':HEAP_BYTES,'producer_symbol':PRODUCER_SYMBOL,'heap_profile_macro':'P18M_INITIALIZED_ESP_HEAP=1','heap_size_macro':'P18M_HEAP_BYTES=0x4e4000','cached_profile_macro':'P17F_CACHED_MATH=1','dma_producer_macro':'P17I_WD_DMA=1','original_startup_headroom_bytes':65536,'bundle_feature_macro':'P18M_ESP_BUNDLE=1'}

package teak;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CdcLoader extends AbstractProgramWrapperLoader {

	private static final String LANGUAGE_ID = "Teak:LE:16:default";
	private static final String COMPILER_ID = "default";

	private static final int HEADER_SIZE = 0x300;
	private static final int MAGIC_OFFSET = 0x100;
	private static final int MAX_SEGMENTS = 10;
	private static final int SEGMENT_RECORD_SIZE = 0x30;

	private static final int TYPE_PROGRAM_A = 0;
	private static final int TYPE_PROGRAM_B = 1;
	private static final int TYPE_DATA = 2;

	private static final int FLAG_RECV_DATA = 1;

	@Override
	public String getName() {
		return "CDC (DSP1)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (isCdc(provider)) {
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_ID), true));
		}
		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		AddressSpace codeSpace = program.getAddressFactory().getAddressSpace("code");
		AddressSpace dataSpace = program.getAddressFactory().getAddressSpace("data");
		if (codeSpace == null || dataSpace == null) {
			log.appendMsg("Teak language is missing the 'code' or 'data' address space");
			return;
		}

		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(MAGIC_OFFSET);
		reader.readNextByteArray(4); // magic
		long binarySize = reader.readNextUnsignedInt();
		int enabledRegions = reader.readNextUnsignedShort();
		reader.readNextUnsignedShort(); // padding
		reader.readNextUnsignedByte(); // unk
		reader.readNextUnsignedByte(); // specialType
		int numSegments = reader.readNextUnsignedByte();
		int flags = reader.readNextUnsignedByte();
		reader.readNextUnsignedInt(); // specialStart
		reader.readNextUnsignedInt(); // specialSize
		reader.readNextLong(); // unk2

		if (binarySize != provider.length()) {
			log.appendMsg(String.format("Header size 0x%X does not match file length 0x%X",
				binarySize, provider.length()));
		}
		log.appendMsg(String.format("Enabled regions: program=0x%02X data=0x%02X",
			enabledRegions & 0xFF, (enabledRegions >> 8) & 0xFF));
		if ((flags & FLAG_RECV_DATA) != 0) {
			log.appendMsg("Flag bit0 set: component expects DSP:RecvData handshake");
		}

		List<Address> codeStarts = new ArrayList<>();
		for (int i = 0; i < numSegments; i++) {
			monitor.checkCancelled();
			long record = 0x120L + (long) i * SEGMENT_RECORD_SIZE;
			reader.setPointerIndex(record);

			long offset = reader.readNextUnsignedInt();
			long start = reader.readNextUnsignedInt();
			long size = reader.readNextUnsignedInt();
			reader.readNextByteArray(3);
			int type = reader.readNextUnsignedByte();
			reader.readNextByteArray(0x20); // sha256 hash

			if (size == 0) {
				log.appendMsg(String.format("Segment %d is empty", i));
				continue;
			}
			if (offset < HEADER_SIZE || offset > provider.length() || size > provider.length() - offset) {
				log.appendMsg(String.format(
					"Segment %d file range 0x%X+0x%X is outside the file", i, offset, size));
				continue;
			}
			if (type != TYPE_PROGRAM_A && type != TYPE_PROGRAM_B && type != TYPE_DATA) {
				log.appendMsg(String.format("Segment %d has unknown memory type %d", i, type));
				continue;
			}

			boolean data = type == TYPE_DATA;
			AddressSpace space = data ? dataSpace : codeSpace;
			String name = (data ? "data_" : "code_") + i;
			String comment = String.format("CDC segment %d type %d file+0x%X",
				i, type, offset);

			try (InputStream segmentBytes = provider.getInputStream(offset)) {
				MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, name,
					wordAddress(space, start), segmentBytes, size, comment, "CDC", true, true,
					!data, log, monitor);
				if (block != null && !data) {
					codeStarts.add(block.getStart());
				}
			}
			catch (AddressOutOfBoundsException | AddressOverflowException e) {
				log.appendMsg(String.format("Segment %d address 0x%X is not in the %s space: %s",
					i, start, space.getName(), e.getMessage()));
			}
		}
	}

	private static Address wordAddress(AddressSpace space, long wordOffset) {
		return space.getAddress(wordOffset, true);
	}

	private static boolean isCdc(ByteProvider provider) throws IOException {
		if (provider.length() < HEADER_SIZE) {
			return false;
		}
		byte[] magic = provider.readBytes(MAGIC_OFFSET, 4);
		if (magic.length != 4 || magic[0] != 'D' || magic[1] != 'S' || magic[2] != 'P' ||
			magic[3] != '1') {
			return false;
		}
		int numSegments = provider.readByte(0x10E);
		return numSegments >= 1 && numSegments <= MAX_SEGMENTS;
	}
}

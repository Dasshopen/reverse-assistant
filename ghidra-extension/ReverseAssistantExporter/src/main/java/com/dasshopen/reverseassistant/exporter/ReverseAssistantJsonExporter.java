package com.dasshopen.reverseassistant.exporter;

import java.io.File;
import java.io.IOException;
import java.util.List;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;

public final class ReverseAssistantJsonExporter
    extends Exporter {

    private final ReverseAssistantExportService exportService;

    public ReverseAssistantJsonExporter() {
        super(
            "Reverse Assistant JSON v2",
            "json",
            null
        );

        exportService = new ReverseAssistantExportService();
    }

    @Override
    public boolean canExportDomainObject(
        Class<? extends DomainObject> domainObjectClass
    ) {
        return Program.class.isAssignableFrom(
            domainObjectClass
        );
    }

    @Override
    public boolean canExportDomainObject(
        DomainObject domainObject
    ) {
        return domainObject instanceof Program;
    }

    @Override
    public boolean supportsAddressRestrictedExport() {
        return false;
    }

    @Override
    public boolean export(
        File file,
        DomainObject domainObject,
        AddressSetView addressSet,
        TaskMonitor monitor
    ) throws IOException, ExporterException {

        log.clear();

        if (!(domainObject instanceof Program program)) {
            log.appendMsg(
                "Unsupported domain object: " +
                    domainObject.getClass().getName()
            );
            return false;
        }

        if (monitor.isCancelled()) {
            log.appendMsg(
                "Reverse Assistant export was cancelled."
            );
            return false;
        }

        monitor.setMessage(
            "Exporting Reverse Assistant JSON v2"
        );

        try {
            exportService.export(
                program,
                file.toPath(),
                 monitor
            );
            return true;
        }
        catch (CancelledException exception) {
            log.appendMsg(
                "Reverse Assistant export was cancelled."
            );
            return false;
        }

        catch (RuntimeException exception) {
            log.appendMsg(
                "Reverse Assistant export failed: " +
                    exception.getMessage()
            );
            throw new ExporterException(exception);
        }
    }

    @Override
    public List<Option> getOptions(
        DomainObjectService domainObjectService
    ) {
        return EMPTY_OPTIONS;
    }

    @Override
    public void setOptions(List<Option> options) {
        // This exporter does not expose export options.
    }
}
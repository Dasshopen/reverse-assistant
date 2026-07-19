package com.dasshopen.reverseassistant.exporter;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Reverse Assistant",
    category = "Analysis",
    shortDescription = "Export Ghidra analysis for Reverse Assistant",
    description = "Exports the active Ghidra program as deterministic and versioned JSON."
)
public final class ReverseAssistantExporterPlugin extends ProgramPlugin {

    private static final String ACTION_OWNER =
        "Reverse Assistant Exporter";

    private final ProgramMetadataCollector metadataCollector;

    public ReverseAssistantExporterPlugin(PluginTool tool) {
        super(tool);

        metadataCollector = new ProgramMetadataCollector();

        createActions();
    }

    private void createActions() {
        DockingAction exportAction = new DockingAction(
            "Export to Reverse Assistant",
            ACTION_OWNER
        ) {
            @Override
            public void actionPerformed(ActionContext context) {
                showProgramMetadata();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return getCurrentProgram() != null;
            }
        };

        exportAction.setMenuBarData(
            new MenuData(
                new String[] {
                    "File",
                    "Export",
                    "Reverse Assistant JSON"
                },
                "Reverse Assistant"
            )
        );

        tool.addAction(exportAction);
    }

    private void showProgramMetadata() {
        try {
            ProgramMetadata metadata =
                metadataCollector.collect(getCurrentProgram());

            String message = String.join(
                System.lineSeparator(),
                "Name: " + metadata.name(),
                "SHA-256: " + metadata.sha256(),
                "Format: " + metadata.format(),
                "Architecture: " + metadata.architecture(),
                "Endianness: " + metadata.endianness(),
                "Image base: " + metadata.imageBase(),
                "Entry point: " + metadata.entryPoint()
            );

            Msg.showInfo(
                this,
                tool.getToolFrame(),
                "Reverse Assistant Program Metadata",
                message
            );
        }
        catch (RuntimeException exception) {
            Msg.showError(
                this,
                tool.getToolFrame(),
                "Reverse Assistant Export Error",
                "Unable to collect the active program metadata.",
                exception
            );
        }
    }
}
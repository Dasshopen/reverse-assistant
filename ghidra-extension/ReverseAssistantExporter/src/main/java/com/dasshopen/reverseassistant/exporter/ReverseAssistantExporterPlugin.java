package com.dasshopen.reverseassistant.exporter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskBuilder;
import ghidra.util.exception.CancelledException;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Reverse Assistant",
    category = "Analysis",
    shortDescription = "Export Ghidra analysis for Reverse Assistant",
    description = "Exports the active Ghidra program as deterministic and versioned JSON."
)
public final class ReverseAssistantExporterPlugin
    extends ProgramPlugin {

    private static final String ACTION_OWNER =
        "Reverse Assistant Exporter";

    private final ReverseAssistantExportService exportService;

    public ReverseAssistantExporterPlugin(PluginTool tool) {
        super(tool);

        exportService = new ReverseAssistantExportService();

        createActions();
    }

    private void createActions() {
        DockingAction exportAction = new DockingAction(
            "Export to Reverse Assistant",
            ACTION_OWNER
        ) {
            @Override
            public void actionPerformed(ActionContext context) {
                exportCurrentProgram();
            }

            @Override
            public boolean isEnabledForContext(
                ActionContext context
            ) {
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

    private void exportCurrentProgram() {
        Program program = getCurrentProgram();

        if (program == null) {
            return;
        }

        try {
            Path destination = chooseDestination(
                program.getName()
            );

            if (destination == null) {
                return;
            }

            if (Files.exists(destination) &&
                !confirmReplacement(destination)) {
                return;
            }

            AtomicBoolean completed =
                new AtomicBoolean(false);

            AtomicReference<Exception> failure =
                new AtomicReference<>();

            new TaskBuilder(
                "Exporting Reverse Assistant JSON",
                monitor -> {
                    try {
                        exportService.export(
                            program,
                            destination,
                            monitor
                        );

                        completed.set(
                            !monitor.isCancelled()
                        );
                    }
                    catch (CancelledException exception) {
                        // Cancellation is an expected user action.
                    }

                    catch (IOException |
                            RuntimeException exception) {
                        failure.set(exception);
                    }
                }
            )
                .setParent(tool.getToolFrame())
                .setCanCancel(true)
                .setHasProgress(true)
                .launchModal();

            Exception exception = failure.get();

            if (exception != null) {
                Msg.showError(
                    this,
                    tool.getToolFrame(),
                    "Reverse Assistant Export Error",
                    "Unable to export the active Ghidra program.",
                    exception
                );
                return;
            }

            if (!completed.get()) {
                return;
            }

            Msg.showInfo(
                this,
                tool.getToolFrame(),
                "Reverse Assistant Export Complete",
                "The Ghidra export was written to:\n" +
                    destination
            );
        }
        catch (RuntimeException exception) {
            Msg.showError(
                this,
                tool.getToolFrame(),
                "Reverse Assistant Export Error",
                "Unable to export the active Ghidra program.",
             exception
            );
        }
    }

    private Path chooseDestination(String programName) {
        GhidraFileChooser chooser =
            new GhidraFileChooser(tool.getToolFrame());

        try {
            chooser.setTitle(
                "Export Reverse Assistant JSON"
            );
            chooser.setApproveButtonText("Export");
            chooser.setApproveButtonToolTipText(
                "Export the current Ghidra analysis as JSON"
            );
            chooser.setMultiSelectionEnabled(false);

            File homeDirectory = new File(
                System.getProperty("user.home")
            );

            chooser.setSelectedFile(
                new File(
                    homeDirectory,
                    createSuggestedFileName(programName)
                )
            );

            File selectedFile = chooser.getSelectedFile(true);

            if (selectedFile == null || chooser.wasCancelled()) {
                return null;
            }

            return ensureJsonExtension(selectedFile.toPath());
        }
        finally {
            chooser.dispose();
        }
    }

    private boolean confirmReplacement(Path destination) {
        int choice = OptionDialog.showYesNoDialog(
            tool.getToolFrame(),
            "Replace Existing Export?",
            "The selected file already exists:\n" +
                destination +
                "\n\nDo you want to replace it?"
        );

        return choice == OptionDialog.YES_OPTION;
    }

    private static String createSuggestedFileName(
        String programName
    ) {
        String safeName = programName
            .replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_")
            .replaceAll("[. ]+$", "");

        if (safeName.isBlank()) {
            safeName = "ghidra-program";
        }

        return safeName + ".reverse-assistant.json";
    }

    private static Path ensureJsonExtension(Path destination) {
        String fileName = destination
            .getFileName()
            .toString();

        if (fileName
            .toLowerCase(Locale.ROOT)
            .endsWith(".json")) {
            return destination;
        }

        return destination.resolveSibling(fileName + ".json");
    }
}